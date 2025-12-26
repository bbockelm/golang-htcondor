package htcondor

import (
	"context"
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

// GetServiceCredStatus reports status for a stored service credential
func (c *CedarCredd) GetServiceCredStatus(ctx context.Context, credType CredType, service string, handle string, user string) (CredentialStatus, error) {
	if err := validateCredTypeForService(credType); err != nil {
		return CredentialStatus{}, err
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

	mode := QueryOAuthMode
	returnAd, err := c.queryCredential(ctx, user, mode, ad)
	if err != nil {
		return CredentialStatus{Exists: false}, err
	}

	// Check return ad for service timestamp
	exists := false
	var updatedAt *time.Time

	serviceName := service
	if handle != "" {
		serviceName = service + "_" + handle
	}

	// Return ad contains timestamps for service files
	if val := returnAd.EvaluateAttr(serviceName); !val.IsError() && val.IsInteger() {
		if timestamp, err := val.IntValue(); err == nil && timestamp > 0 {
			exists = true
			t := time.Unix(timestamp, 0)
			updatedAt = &t
		}
	}

	return CredentialStatus{Exists: exists, UpdatedAt: updatedAt}, nil
}

// ListServiceCreds returns all service credentials for the user
func (c *CedarCredd) ListServiceCreds(ctx context.Context, credType CredType, user string) ([]ServiceStatus, error) {
	if err := validateCredTypeForService(credType); err != nil {
		return nil, err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}

	// Query without service name lists all
	ad := classad.New()
	// Empty service means list all

	mode := QueryOAuthMode
	returnAd, err := c.queryCredential(ctx, user, mode, ad)
	if err != nil {
		return nil, err
	}

	// Parse return ad for all service entries
	statuses := make([]ServiceStatus, 0)
	if returnAd == nil {
		return statuses, nil
	}

	// Group services by base name (strip .top/.use extensions)
	serviceMap := make(map[string]ServiceStatus)

	for _, attrName := range returnAd.GetAttributes() {
		// Skip special attributes
		if attrName == "MyType" || attrName == "TargetType" {
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

		// Parse service name - strip .top or .use extensions
		baseName := attrName
		if strings.HasSuffix(attrName, ".top") {
			baseName = strings.TrimSuffix(attrName, ".top")
		} else if strings.HasSuffix(attrName, ".use") {
			baseName = strings.TrimSuffix(attrName, ".use")
		}

		// Parse service and handle from base name
		var service, handle string
		if s, h, ok := strings.Cut(baseName, "_"); ok {
			service = s
			handle = h
		} else {
			service = baseName
			handle = ""
		}

		// Update service entry with latest timestamp
		t := time.Unix(timestamp, 0)
		if existing, ok := serviceMap[baseName]; ok {
			if t.After(*existing.UpdatedAt) {
				existing.UpdatedAt = &t
				serviceMap[baseName] = existing
			}
		} else {
			serviceMap[baseName] = ServiceStatus{
				Service:   service,
				Handle:    handle,
				Exists:    true,
				UpdatedAt: &t,
			}
		}
	}

	// Convert map to slice
	for _, status := range serviceMap {
		statuses = append(statuses, status)
	}

	return statuses, nil
}

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

	// Check return value
	// Convention: error codes are 0-20, success with timestamp is > 100
	if returnVal == FailureNotFound {
		return ErrCredentialNotFound
	}
	if returnVal < 0 || (returnVal > 20 && returnVal < 100) {
		return fmt.Errorf("store credential failed with code %d", returnVal)
	}
	// returnVal is Success (1), SuccessPending (6), or timestamp (> 100)
	// All are success cases

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
		return nil, fmt.Errorf("query credential failed with code %d", returnVal)
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
