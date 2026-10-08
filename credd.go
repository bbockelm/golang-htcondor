package htcondor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// CredType enumerates the credential types supported by the credd.
// Mirrors the Python bindings CredType enum (Kerberos, OAuth).
type CredType string

const (
	// CredTypeKerberos stores Kerberos credentials.
	CredTypeKerberos CredType = "Kerberos"
	// CredTypeOAuth stores OAuth2 credentials.
	CredTypeOAuth CredType = "OAuth"
)

// ErrCredentialNotFound is returned when the requested credential does not exist.
var ErrCredentialNotFound = errors.New("credential not found")

// CredentialStatus describes whether a credential exists and when it was last updated.
type CredentialStatus struct {
	Exists    bool       `json:"exists"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	// Pending reports a credential that has been requested or stored but
	// is not usable yet: the credd holds its request (.top) file and a
	// credmon has not written the token (.use) from it. Exists is false
	// while this is true.
	Pending bool `json:"pending,omitempty"`
}

// CredRequest names one OAuth service credential a job needs, as sent to
// CheckCreds.
type CredRequest struct {
	Service  string
	Handle   string
	Scopes   string
	Audience string
}

// ServiceStatus describes the state of a service credential.
type ServiceStatus struct {
	Service   string     `json:"service"`
	Handle    string     `json:"handle,omitempty"`
	Exists    bool       `json:"exists"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// CreddClient defines the operations exposed by the credd (credential daemon).
// The methods mirror the Python bindings htcondor2.Credd API but omit Windows password support.
type CreddClient interface {
	PutUserCred(ctx context.Context, credType CredType, credential []byte, user string) error
	DeleteUserCred(ctx context.Context, credType CredType, user string) error
	GetUserCredStatus(ctx context.Context, credType CredType, user string) (CredentialStatus, error)

	PutServiceCred(ctx context.Context, credType CredType, credential []byte, service string, handle string, user string, refresh *bool) error
	DeleteServiceCred(ctx context.Context, credType CredType, service string, handle string, user string) error
	GetServiceCredStatus(ctx context.Context, credType CredType, service string, handle string, user string) (CredentialStatus, error)
	ListServiceCreds(ctx context.Context, credType CredType, user string) ([]ServiceStatus, error)

	GetCredential(ctx context.Context, credType CredType, service string, handle string, user string) ([]byte, error)

	// CheckCreds makes the request condor_submit makes before it submits a
	// job: it asks the credd to make sure the caller holds every OAuth
	// credential in requests, and the credd adds the services its own
	// local credmons provide (SUBMIT_ADD_LOCAL_CREDMON_PROVIDERS, on by
	// default). For a local credmon's service a missing credential is
	// created on the spot, which is how an access point that requires one
	// on every job gets it -- so an empty request list is meaningful.
	//
	// It returns "" when everything is in place, or a URL the user must
	// visit to grant a credential the credd cannot create itself.
	CheckCreds(ctx context.Context, requests []CredRequest) (string, error)
}

// InMemoryCredd provides a lightweight, non-persistent credd implementation useful for testing
// and demo environments. It is not intended for production credential storage.
type InMemoryCredd struct {
	mu    sync.RWMutex
	creds map[credentialKey]storedCredential
	clock func() time.Time
}

type credentialKey struct {
	user     string
	credType CredType
	service  string
	handle   string
}

type storedCredential struct {
	payload   []byte
	refresh   *bool
	updatedAt time.Time
}

// NewInMemoryCredd constructs a new in-memory credd client.
func NewInMemoryCredd() *InMemoryCredd {
	return &InMemoryCredd{
		creds: make(map[credentialKey]storedCredential),
		clock: time.Now,
	}
}

func validateCredTypeForUser(credType CredType) error {
	switch credType {
	case CredTypeKerberos:
		return nil
	default:
		return fmt.Errorf("unsupported cred type for user credential: %s", credType)
	}
}

func validateCredTypeForService(credType CredType) error {
	if credType != CredTypeOAuth {
		return fmt.Errorf("unsupported cred type for service credential: %s", credType)
	}
	return nil
}

// PutUserCred stores a user credential of the given type (Kerberos).
func (c *InMemoryCredd) PutUserCred(ctx context.Context, credType CredType, credential []byte, user string) error {
	if err := validateCredTypeForUser(credType); err != nil {
		return err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.creds[credentialKey{user: user, credType: credType}] = storedCredential{payload: credential, updatedAt: c.clock()}
	return nil
}

// PutServiceCred stores an OAuth service credential for a user.
func (c *InMemoryCredd) PutServiceCred(ctx context.Context, credType CredType, credential []byte, service string, handle string, user string, refresh *bool) error {
	if err := validateCredTypeForService(credType); err != nil {
		return err
	}
	if service == "" {
		return errors.New("service is required for service credential")
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.creds[credentialKey{user: user, credType: credType, service: service, handle: handle}] = storedCredential{
		payload:   credential,
		refresh:   refresh,
		updatedAt: c.clock(),
	}
	return nil
}

// DeleteUserCred removes a user credential of the specified type.
func (c *InMemoryCredd) DeleteUserCred(ctx context.Context, credType CredType, user string) error {
	if err := validateCredTypeForUser(credType); err != nil {
		return err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	_, err := c.deleteCredential(credentialKey{user: user, credType: credType})
	return err
}

// DeleteServiceCred removes a service credential for a user.
func (c *InMemoryCredd) DeleteServiceCred(ctx context.Context, credType CredType, service string, handle string, user string) error {
	if err := validateCredTypeForService(credType); err != nil {
		return err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	_, err := c.deleteCredential(credentialKey{user: user, credType: credType, service: service, handle: handle})
	return err
}

// GetCredential returns the stored credential payload for service/handle.
func (c *InMemoryCredd) GetCredential(ctx context.Context, credType CredType, service string, handle string, user string) ([]byte, error) {
	if err := validateCredTypeForService(credType); err != nil {
		return nil, err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := credentialKey{user: user, credType: credType, service: service, handle: handle}
	stored, ok := c.creds[key]
	if !ok {
		return nil, ErrCredentialNotFound
	}
	return stored.payload, nil
}

// CheckCreds reports whether every requested service credential is stored.
// There is no credmon here to create a missing one, so a missing credential
// is an error, as the credd reports a service it has no credmon for.
func (c *InMemoryCredd) CheckCreds(ctx context.Context, requests []CredRequest) (string, error) {
	user := GetAuthenticatedUserFromContext(ctx)
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, req := range requests {
		key := credentialKey{user: user, credType: CredTypeOAuth, service: req.Service, handle: req.Handle}
		if _, ok := c.creds[key]; !ok {
			return "", &CheckCredsRefusal{Reason: fmt.Sprintf("ERROR: Credential '%s' of unknown type is missing", req.Service)}
		}
	}
	return "", nil
}

// GetUserCredStatus reports credential status for the specified user credential type.
func (c *InMemoryCredd) GetUserCredStatus(ctx context.Context, credType CredType, user string) (CredentialStatus, error) {
	if err := validateCredTypeForUser(credType); err != nil {
		return CredentialStatus{}, err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	return c.queryCredential(credentialKey{user: user, credType: credType})
}

// GetServiceCredStatus reports status for a stored service credential.
func (c *InMemoryCredd) GetServiceCredStatus(ctx context.Context, credType CredType, service string, handle string, user string) (CredentialStatus, error) {
	if err := validateCredTypeForService(credType); err != nil {
		return CredentialStatus{}, err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	return c.queryCredential(credentialKey{user: user, credType: credType, service: service, handle: handle})
}

// ListServiceCreds returns all service credentials for the user and credType.
func (c *InMemoryCredd) ListServiceCreds(ctx context.Context, credType CredType, user string) ([]ServiceStatus, error) {
	if err := validateCredTypeForService(credType); err != nil {
		return nil, err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	statuses := make([]ServiceStatus, 0)
	for key, stored := range c.creds {
		if key.user != user || key.credType != credType || key.service == "" {
			continue
		}
		ts := stored.updatedAt
		statuses = append(statuses, ServiceStatus{
			Service:   key.service,
			Handle:    key.handle,
			Exists:    true,
			UpdatedAt: &ts,
		})
	}
	return statuses, nil
}

//nolint:unparam // bool return kept for potential future use
func (c *InMemoryCredd) deleteCredential(key credentialKey) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.creds[key]; !ok {
		return false, ErrCredentialNotFound
	}
	delete(c.creds, key)
	return true, nil
}

func (c *InMemoryCredd) queryCredential(key credentialKey) (CredentialStatus, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	stored, ok := c.creds[key]
	if !ok {
		return CredentialStatus{Exists: false}, ErrCredentialNotFound
	}
	ts := stored.updatedAt
	return CredentialStatus{Exists: true, UpdatedAt: &ts}, nil
}

// ValidateOAuthCredential reports whether a credential's bytes are storable as
// an OAuth service credential, and explains the problem when they are not.
//
// An OAuth service credential has to be a JSON document. The credd will not
// tell you that at store time: it accepts whatever bytes it is given, and only
// parses them when a request carries scopes or an audience. It re-parses them,
// though, whenever a query names a specific service -- so storing a bare token
// string succeeds, and then get_credential_status fails ever after with
// FAILURE_JSON_PARSE while list_service_credentials, which never names a
// service, keeps reporting the credential as present.
//
// Two read paths disagreeing about the same credential is a miserable thing to
// debug, and the evidence points away from the cause: the store said OK. So
// every path that stores one should refuse at the door instead.
//
// Lives here, next to PutServiceCred, because it is a fact about the credd
// rather than about any particular API in front of it -- there is more than
// one, and they were not agreeing.
//
// An empty credential is deliberately allowed, and is not the same thing as a
// malformed one. A credmon that mints tokens locally -- see the localcredmon
// module -- watches for the stored .top file and never reads its contents, so
// storing nothing is how you ask for a token rather than supply one. That is
// the normal path for OAuth services a server-side job transform added.
func ValidateOAuthCredential(service string, cred []byte) error {
	if len(cred) == 0 {
		return nil
	}
	if !json.Valid(cred) {
		return fmt.Errorf("credential for %q is not valid JSON: an OAuth service credential must be "+
			"a JSON document such as {\"access_token\":\"...\"}. Storing anything else appears to "+
			"succeed and then breaks every later read of it", service)
	}
	return nil
}
