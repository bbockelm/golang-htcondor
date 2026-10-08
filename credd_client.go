package htcondor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
)

// Command codes for credd daemon (from condor_commands.h)
// HTCondor command codes
const (
	// StoreCred is the main credential storage command (SCHED_VERS+79 = 479)
	// This is what store_cred_handler uses
	StoreCred       = 479   // SCHED_VERS+79
	CreddGetToken   = 81004 // CREDD_BASE+4
	CreddCheckCreds = 81030 // CREDD_BASE+30
)

// Mode constants for StoreCred command (from store_cred.h)
const (
	ModeMask           = 3
	GenericAdd         = 0
	GenericDelete      = 1
	GenericQuery       = 2
	StoreCredUserKrb   = 0x20
	StoreCredUserOAuth = 0x28
	StoreCredLegacy    = 0x40
	AddOAuthMode       = StoreCredUserOAuth | GenericAdd
	DeleteOAuthMode    = StoreCredUserOAuth | GenericDelete
	QueryOAuthMode     = StoreCredUserOAuth | GenericQuery
	AddKrbMode         = StoreCredUserKrb | GenericAdd
	DeleteKrbMode      = StoreCredUserKrb | GenericDelete
	QueryKrbMode       = StoreCredUserKrb | GenericQuery
)

// Return codes from store_cred operations (from store_cred.h)
const (
	Success            = 1
	Failure            = 0
	FailureBadPassword = 2
	FailureNotSecure   = 4
	FailureNotFound    = 5
	SuccessPending     = 6
	FailureNotAllowed  = 7
	FailureBadArgs     = 8
	FailureConfigError = 11
)

// CedarCredd provides a CEDAR-based credd client implementation
type CedarCredd struct {
	address string
}

// NewCedarCredd creates a new CEDAR-based credd client
func NewCedarCredd(address string) *CedarCredd {
	return &CedarCredd{
		address: address,
	}
}

// PutUserCred stores a user credential (Kerberos)
func (c *CedarCredd) PutUserCred(ctx context.Context, credType CredType, credential []byte, user string) error {
	if err := validateCredTypeForUser(credType); err != nil {
		return err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}

	mode := AddKrbMode
	return c.storeCredential(ctx, user, mode, credential, nil)
}

// DeleteUserCred removes a user credential
func (c *CedarCredd) DeleteUserCred(ctx context.Context, credType CredType, user string) error {
	if err := validateCredTypeForUser(credType); err != nil {
		return err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}

	mode := DeleteKrbMode
	return c.storeCredential(ctx, user, mode, nil, nil)
}

// GetUserCredStatus reports credential status
func (c *CedarCredd) GetUserCredStatus(ctx context.Context, credType CredType, user string) (CredentialStatus, error) {
	if err := validateCredTypeForUser(credType); err != nil {
		return CredentialStatus{}, err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}

	mode := QueryKrbMode
	returnAd, err := c.queryCredential(ctx, user, mode, nil)
	if err != nil {
		return CredentialStatus{Exists: false}, err
	}

	// Check return ad for timestamp or success indicator
	exists := returnAd != nil && len(returnAd.GetAttributes()) > 0
	var updatedAt *time.Time
	// Return ad may contain timestamps or other metadata
	// For now, just indicate existence

	return CredentialStatus{Exists: exists, UpdatedAt: updatedAt}, nil
}

// PutServiceCred stores an OAuth service credential
func (c *CedarCredd) PutServiceCred(ctx context.Context, credType CredType, credential []byte, service string, handle string, user string, refresh *bool) error {
	if err := validateCredTypeForService(credType); err != nil {
		return err
	}
	if service == "" {
		return fmt.Errorf("service is required for service credential")
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}

	// Build ClassAd with Service and optional Handle
	ad := classad.New()
	_ = ad.Set("Service", service)
	if handle != "" {
		_ = ad.Set("Handle", handle)
	}
	if refresh != nil {
		_ = ad.Set("NeedRefresh", *refresh)
	}

	mode := AddOAuthMode
	return c.storeCredential(ctx, user, mode, credential, ad)
}

// DeleteServiceCred removes a service credential
func (c *CedarCredd) DeleteServiceCred(ctx context.Context, credType CredType, service string, handle string, user string) error {
	if err := validateCredTypeForService(credType); err != nil {
		return err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}

	// Build ClassAd with Service and optional Handle
	ad := classad.New()
	_ = ad.Set("Service", service)
	if handle != "" {
		_ = ad.Set("Handle", handle)
	}

	mode := DeleteOAuthMode
	return c.storeCredential(ctx, user, mode, nil, ad)
}

// GetServiceCredStatus reports status for a stored service credential.
//
// It asks the credd for every credential file the user holds rather than
// naming the service. A query that names a service makes the credd re-read
// the service's .top file as JSON to compare scopes, and a local credmon's
// .top is not JSON -- it holds only the user's name -- so naming the service
// fails with FAILURE_JSON_PARSE on a credential that works. The listing reads
// no file contents.
//
// A service with no files at all is reported as ErrCredentialNotFound.
func (c *CedarCredd) GetServiceCredStatus(ctx context.Context, credType CredType, service string, handle string, user string) (CredentialStatus, error) {
	if err := validateCredTypeForService(credType); err != nil {
		return CredentialStatus{}, err
	}
	if service == "" {
		return CredentialStatus{}, fmt.Errorf("service is required for service credential")
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}

	returnAd, err := c.queryCredential(ctx, user, QueryOAuthMode, classad.New())
	if err != nil {
		return CredentialStatus{Exists: false}, err
	}

	name := service
	if handle != "" {
		name = service + "_" + handle
	}
	files, ok := serviceCredFiles(returnAd)[name]
	if !ok {
		return CredentialStatus{Exists: false}, ErrCredentialNotFound
	}
	if files.use != nil {
		return CredentialStatus{Exists: true, UpdatedAt: files.use}, nil
	}
	return CredentialStatus{Pending: true, UpdatedAt: files.top}, nil
}

// credFileTimes holds the modification times of one service credential's
// files: the request or refresh token (.top) and the usable token (.use).
type credFileTimes struct {
	top *time.Time
	use *time.Time
}

// serviceCredFiles reads the reply to a credd query that named no service,
// which carries one attribute per credential file, "<name>.top" or
// "<name>.use", valued with the file's modification time. It is keyed by
// <name>, which is the service, or "<service>_<handle>".
func serviceCredFiles(returnAd *classad.ClassAd) map[string]credFileTimes {
	files := make(map[string]credFileTimes)
	if returnAd == nil {
		return files
	}
	for _, attrName := range returnAd.GetAttributes() {
		base, ext, ok := cutCredFileExt(attrName)
		if !ok {
			continue
		}
		val := returnAd.EvaluateAttr(attrName)
		if val.IsError() || !val.IsInteger() {
			continue
		}
		timestamp, err := val.IntValue()
		if err != nil || timestamp <= 0 {
			continue
		}
		t := time.Unix(timestamp, 0)
		entry := files[base]
		if ext == ".top" {
			entry.top = &t
		} else {
			entry.use = &t
		}
		files[base] = entry
	}
	return files
}

func cutCredFileExt(attrName string) (string, string, bool) {
	for _, ext := range []string{".top", ".use"} {
		if base, ok := strings.CutSuffix(attrName, ext); ok && base != "" {
			return base, ext, true
		}
	}
	return "", "", false
}

// ListServiceCreds returns all service credentials for the user. A user with
// none gets an empty list: the credd answers that query with "not found",
// which is an answer, not a failure.
func (c *CedarCredd) ListServiceCreds(ctx context.Context, credType CredType, user string) ([]ServiceStatus, error) {
	if err := validateCredTypeForService(credType); err != nil {
		return nil, err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}

	returnAd, err := c.queryCredential(ctx, user, QueryOAuthMode, classad.New())
	if errors.Is(err, ErrCredentialNotFound) {
		return []ServiceStatus{}, nil
	}
	if err != nil {
		return nil, err
	}

	files := serviceCredFiles(returnAd)
	statuses := make([]ServiceStatus, 0, len(files))
	for name, f := range files {
		service, handle, _ := strings.Cut(name, "_")
		updated := f.use
		if updated == nil || (f.top != nil && f.top.After(*updated)) {
			updated = f.top
		}
		statuses = append(statuses, ServiceStatus{
			Service:   service,
			Handle:    handle,
			Exists:    true,
			UpdatedAt: updated,
		})
	}
	return statuses, nil
}

// CheckCreds implements CREDD_CHECK_CREDS, the request condor_submit makes
// before submitting (do_check_oauth_creds in store_cred.cpp): a count, one ad
// per requested service, then a single string in reply.
//
// The credd may hold the reply while a local credmon writes a token it has
// just asked for, up to about 20 seconds, so ctx should allow for that.
func (c *CedarCredd) CheckCreds(ctx context.Context, requests []CredRequest) (string, error) {
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, CreddCheckCreds, "CLIENT", c.address)
	if err != nil {
		return "", fmt.Errorf("failed to create security config: %w", err)
	}
	// The credd registers this command with force-authentication: it acts
	// for whoever the socket says the caller is.
	secConfig.Encryption = "REQUIRED"
	secConfig.Authentication = "REQUIRED"

	htcondorClient, err := client.ConnectAndAuthenticate(ctx, c.address, secConfig)
	if err != nil {
		return "", fmt.Errorf("failed to connect to credd: %w", err)
	}
	defer func() { _ = htcondorClient.Close() }()

	stream := htcondorClient.GetStream()
	msg := message.NewMessageForStream(stream)
	//nolint:gosec // a request list is a handful of services
	if err := msg.PutInt32(ctx, int32(len(requests))); err != nil {
		return "", fmt.Errorf("failed to send request count: %w", err)
	}
	for _, req := range requests {
		// Handle, Scopes and Audience are always sent, empty when unset:
		// credds before 8.9.9 carry a missing one over from the previous ad.
		ad := classad.New()
		_ = ad.Set("Service", req.Service)
		_ = ad.Set("Handle", req.Handle)
		_ = ad.Set("Scopes", req.Scopes)
		_ = ad.Set("Audience", req.Audience)
		if err := msg.PutClassAd(ctx, ad); err != nil {
			return "", fmt.Errorf("failed to send request ad: %w", err)
		}
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return "", fmt.Errorf("failed to finish message: %w", err)
	}

	reply := message.NewMessageFromStream(stream)
	answer, err := reply.GetString(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to receive check-creds reply: %w", err)
	}
	return checkCredsAnswer(answer)
}

// checkCredsAnswer interprets the credd's reply to CREDD_CHECK_CREDS: empty
// means every credential is in place, a URL is one the user must visit, and
// anything else is the reason it failed (condor_submit's reading of it).
func checkCredsAnswer(answer string) (string, error) {
	answer = strings.TrimSpace(answer)
	switch {
	case answer == "":
		return "", nil
	case strings.HasPrefix(answer, "https://") || strings.HasPrefix(answer, "http://"):
		return answer, nil
	default:
		return "", &CheckCredsRefusal{Reason: answer}
	}
}

// CheckCredsRefusal is the credd answering CREDD_CHECK_CREDS with a reason it
// cannot supply the credentials, as distinct from failing to reach it. Asking
// again gets the same answer until something on the access point changes.
type CheckCredsRefusal struct {
	Reason string
}

func (e *CheckCredsRefusal) Error() string { return "credd: " + e.Reason }

// GetCredential returns the stored credential payload
func (c *CedarCredd) GetCredential(ctx context.Context, credType CredType, service string, handle string, user string) ([]byte, error) {
	if err := validateCredTypeForService(credType); err != nil {
		return nil, err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}

	// Use CreddGetToken command for OAuth credentials
	ad := classad.New()
	_ = ad.Set("Service", service)
	if handle != "" {
		_ = ad.Set("Handle", handle)
	}

	return c.getToken(ctx, user, ad)
}

// storeCredential implements the StoreCred wire protocol
func (c *CedarCredd) storeCredential(ctx context.Context, user string, mode int, credential []byte, ad *classad.ClassAd) error {
	// Get security config
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, StoreCred, "CLIENT", c.address)
	if err != nil {
		return fmt.Errorf("failed to create security config: %w", err)
	}

	// Require encryption for credential operations
	secConfig.Encryption = "REQUIRED"
	secConfig.Authentication = "REQUIRED"

	// Connect and authenticate
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, c.address, secConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to credd: %w", err)
	}
	defer func() { _ = htcondorClient.Close() }()

	stream := htcondorClient.GetStream()

	// TODO: Check if we need to consume a post-auth message here
	// The response we're getting looks like an auth message with fully_qualified_user

	// Send command payload: user, password (empty for non-legacy), mode
	msg := message.NewMessageForStream(stream)
	if err := msg.PutString(ctx, user); err != nil {
		return fmt.Errorf("failed to send user: %w", err)
	}

	// Password field is empty for non-legacy mode
	if err := msg.PutString(ctx, ""); err != nil {
		return fmt.Errorf("failed to send password: %w", err)
	}

	//nolint:gosec // mode values are small integers, no overflow risk
	if err := msg.PutInt32(ctx, int32(mode)); err != nil {
		return fmt.Errorf("failed to send mode: %w", err)
	}

	// Non-legacy mode: send credlen, cred bytes, classad
	credLen := len(credential)
	//nolint:gosec // G115: credential length is bounded by reasonable message sizes
	if err := msg.PutInt32(ctx, int32(credLen)); err != nil {
		return fmt.Errorf("failed to send credlen: %w", err)
	}

	if credLen > 0 {
		if err := msg.PutBytes(ctx, credential); err != nil {
			return fmt.Errorf("failed to send credential: %w", err)
		}
	}

	// Send ClassAd (or empty ad)
	if ad == nil {
		ad = classad.New()
	}
	if err := msg.PutClassAd(ctx, ad); err != nil {
		return fmt.Errorf("failed to send classad: %w", err)
	}

	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish message: %w", err)
	}

	// Receive response: return_val (long long), classad
	responseMsg := message.NewMessageFromStream(stream)
	returnVal, err := responseMsg.GetInt64(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive return value: %w", err)
	}

	returnAd, err := responseMsg.GetClassAd(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive return classad: %w", err)
	}
	_ = returnAd // May contain additional info like fully_qualified_user

	// Check return value.
	//
	// The credd answers a store with SUCCESS (1) or SUCCESS_PENDING (6),
	// and some modes answer with a modification timestamp instead.
	// Everything else is a failure -- including FAILURE (0) and the
	// 2..14 error codes in HTCondor's store_cred.h.
	//
	// The previous test was `returnVal < 0 || (returnVal > 20 &&
	// returnVal < 100)`, which contradicted the comment above it: it let
	// every one of those error codes through as success. A store
	// refused for FAILURE_NOT_ALLOWED or written unparseably was
	// reported to the caller as having worked.
	if returnVal == FailureNotFound {
		return ErrCredentialNotFound
	}
	if returnVal != Success && returnVal != SuccessPending && returnVal <= 100 {
		return creddError("store credential failed", returnVal)
	}

	return nil
}

// queryCredential implements the StoreCred query protocol
func (c *CedarCredd) queryCredential(ctx context.Context, user string, mode int, ad *classad.ClassAd) (*classad.ClassAd, error) {
	// Get security config
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, StoreCred, "CLIENT", c.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Require encryption for credential operations
	secConfig.Encryption = "REQUIRED"
	secConfig.Authentication = "REQUIRED"

	// Connect and authenticate
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, c.address, secConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to credd: %w", err)
	}
	defer func() { _ = htcondorClient.Close() }()

	stream := htcondorClient.GetStream()

	// Send command payload: user, password (empty), mode
	msg := message.NewMessageForStream(stream)
	if err := msg.PutString(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to send user: %w", err)
	}

	if err := msg.PutString(ctx, ""); err != nil {
		return nil, fmt.Errorf("failed to send password: %w", err)
	}

	//nolint:gosec // mode values are small integers, no overflow risk
	if err := msg.PutInt32(ctx, int32(mode)); err != nil {
		return nil, fmt.Errorf("failed to send mode: %w", err)
	}

	// Non-legacy mode: send credlen=0, no bytes, classad
	if err := msg.PutInt32(ctx, 0); err != nil {
		return nil, fmt.Errorf("failed to send credlen: %w", err)
	}

	// Send ClassAd (or empty ad)
	if ad == nil {
		ad = classad.New()
	}
	if err := msg.PutClassAd(ctx, ad); err != nil {
		return nil, fmt.Errorf("failed to send classad: %w", err)
	}

	if err := msg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to finish message: %w", err)
	}

	// Receive response: return_val (long long), classad
	responseMsg := message.NewMessageFromStream(stream)
	returnVal, err := responseMsg.GetInt64(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to receive return value: %w", err)
	}

	returnAd, err := responseMsg.GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to receive return classad: %w", err)
	}

	// Check return value
	if returnVal == FailureNotFound {
		return nil, ErrCredentialNotFound
	}
	if returnVal != Success && returnVal != SuccessPending {
		return nil, creddError("query credential failed", returnVal)
	}

	return returnAd, nil
}

// getToken implements the CreddGetToken protocol
func (c *CedarCredd) getToken(ctx context.Context, _ string, commandAd *classad.ClassAd) ([]byte, error) {
	// Get security config
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, CreddGetToken, "CLIENT", c.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Require encryption for credential operations
	secConfig.Encryption = "REQUIRED"
	secConfig.Authentication = "REQUIRED"

	// Connect and authenticate
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, c.address, secConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to credd: %w", err)
	}
	defer func() { _ = htcondorClient.Close() }()

	stream := htcondorClient.GetStream()

	// Send command ad with Service and Handle
	msg := message.NewMessageForStream(stream)
	if err := msg.PutClassAd(ctx, commandAd); err != nil {
		return nil, fmt.Errorf("failed to send command ad: %w", err)
	}

	if err := msg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to finish message: %w", err)
	}

	// Receive reply ad with Token attribute (binary)
	responseMsg := message.NewMessageFromStream(stream)
	replyAd, err := responseMsg.GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to receive reply ad: %w", err)
	}

	// Check for ErrorString attribute (indicates failure)
	errVal := replyAd.EvaluateAttr("ErrorString")
	if !errVal.IsError() && errVal.IsString() {
		errStr, _ := errVal.StringValue()
		// Check if it's a "not found" or "pending" error
		if strings.Contains(errStr, "not an existing regular file") {
			return nil, ErrCredentialNotFound
		}
		return nil, fmt.Errorf("credd error: %s", errStr)
	}

	// Extract Token attribute (binary data)
	tokenVal := replyAd.EvaluateAttr("Token")
	if tokenVal.IsError() {
		return nil, ErrCredentialNotFound
	}

	if !tokenVal.IsString() {
		return nil, fmt.Errorf("token attribute is not a string, type: %v", tokenVal.Type())
	}

	tokenStr, err := tokenVal.StringValue()
	if err != nil {
		return nil, fmt.Errorf("failed to get token value: %w", err)
	}

	return []byte(tokenStr), nil
}
