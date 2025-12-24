package htcondor

import (
	"context"
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
