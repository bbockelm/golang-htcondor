package htcondor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// CredType enumerates the credential types supported by the credd.
// Mirrors the Python bindings CredType enum (Password, Kerberos, OAuth).
type CredType string

const (
	// CredTypePassword stores legacy password credentials.
	CredTypePassword CredType = "Password"
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
// The methods mirror the Python bindings htcondor2.Credd API.
type CreddClient interface {
	AddPassword(ctx context.Context, password string, user string) error
	AddUserCred(ctx context.Context, credType CredType, credential []byte, user string) error
	AddUserServiceCred(ctx context.Context, credType CredType, credential []byte, service string, handle string, user string, refresh *bool) error
	CheckUserServiceCreds(ctx context.Context, credType CredType, serviceAds []*classad.ClassAd, user string) ([]ServiceStatus, error)
	DeletePassword(ctx context.Context, user string) (bool, error)
	DeleteUserCred(ctx context.Context, credType CredType, user string) error
	DeleteUserServiceCred(ctx context.Context, credType CredType, service string, handle string, user string) error
	GetOAuth2Credential(ctx context.Context, service string, handle string, user string) (string, error)
	QueryPassword(ctx context.Context, user string) (CredentialStatus, error)
	QueryUserCred(ctx context.Context, credType CredType, user string) (CredentialStatus, error)
	QueryUserServiceCred(ctx context.Context, credType CredType, service string, handle string, user string) (CredentialStatus, error)
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
	case CredTypePassword, CredTypeKerberos:
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

// AddPassword stores a password credential for a user.
func (c *InMemoryCredd) AddPassword(ctx context.Context, password string, user string) error {
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.creds[credentialKey{user: user, credType: CredTypePassword}] = storedCredential{payload: []byte(password), updatedAt: c.clock()}
	return nil
}

// AddUserCred stores a user credential of the given type (password or Kerberos).
func (c *InMemoryCredd) AddUserCred(ctx context.Context, credType CredType, credential []byte, user string) error {
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

// AddUserServiceCred stores an OAuth service credential for a user.
func (c *InMemoryCredd) AddUserServiceCred(ctx context.Context, credType CredType, credential []byte, service string, handle string, user string, refresh *bool) error {
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

// CheckUserServiceCreds reports the presence and update time of service credentials.
func (c *InMemoryCredd) CheckUserServiceCreds(ctx context.Context, credType CredType, serviceAds []*classad.ClassAd, user string) ([]ServiceStatus, error) {
	if err := validateCredTypeForService(credType); err != nil {
		return nil, err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}

	specs := extractServiceSpecs(serviceAds)
	statuses := make([]ServiceStatus, 0, len(specs))

	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, spec := range specs {
		key := credentialKey{user: user, credType: credType, service: spec.Service, handle: spec.Handle}
		stored, ok := c.creds[key]
		status := ServiceStatus{Service: spec.Service, Handle: spec.Handle, Exists: ok}
		if ok {
			status.UpdatedAt = &stored.updatedAt
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// DeletePassword removes a stored password credential for a user.
func (c *InMemoryCredd) DeletePassword(ctx context.Context, user string) (bool, error) {
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	return c.deleteCredential(credentialKey{user: user, credType: CredTypePassword})
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

// DeleteUserServiceCred removes a service credential for a user.
func (c *InMemoryCredd) DeleteUserServiceCred(ctx context.Context, credType CredType, service string, handle string, user string) error {
	if err := validateCredTypeForService(credType); err != nil {
		return err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	_, err := c.deleteCredential(credentialKey{user: user, credType: credType, service: service, handle: handle})
	return err
}

// GetOAuth2Credential returns the stored OAuth credential for service/handle.
func (c *InMemoryCredd) GetOAuth2Credential(ctx context.Context, service string, handle string, user string) (string, error) {
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := credentialKey{user: user, credType: CredTypeOAuth, service: service, handle: handle}
	stored, ok := c.creds[key]
	if !ok {
		return "", ErrCredentialNotFound
	}
	return string(stored.payload), nil
}

// QueryPassword reports password credential status for a user.
func (c *InMemoryCredd) QueryPassword(ctx context.Context, user string) (CredentialStatus, error) {
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	return c.queryCredential(credentialKey{user: user, credType: CredTypePassword})
}

// QueryUserCred reports credential status for the specified user credential type.
func (c *InMemoryCredd) QueryUserCred(ctx context.Context, credType CredType, user string) (CredentialStatus, error) {
	if err := validateCredTypeForUser(credType); err != nil {
		return CredentialStatus{}, err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	return c.queryCredential(credentialKey{user: user, credType: credType})
}

// QueryUserServiceCred reports status for a stored service credential.
func (c *InMemoryCredd) QueryUserServiceCred(ctx context.Context, credType CredType, service string, handle string, user string) (CredentialStatus, error) {
	if err := validateCredTypeForService(credType); err != nil {
		return CredentialStatus{}, err
	}
	if user == "" {
		user = GetAuthenticatedUserFromContext(ctx)
	}
	return c.queryCredential(credentialKey{user: user, credType: credType, service: service, handle: handle})
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

// extractServiceSpecs converts ClassAds to service specs. The ClassAds are expected
// to include a "Service" attribute and optional "Handle" attribute.
func extractServiceSpecs(serviceAds []*classad.ClassAd) []ServiceStatus {
	specs := make([]ServiceStatus, 0, len(serviceAds))
	for _, ad := range serviceAds {
		if ad == nil {
			continue
		}
		serviceStr, _ := ad.EvaluateAttrString("Service")
		handleStr, _ := ad.EvaluateAttrString("Handle")
		specs = append(specs, ServiceStatus{Service: serviceStr, Handle: handleStr})
	}
	return specs
}
