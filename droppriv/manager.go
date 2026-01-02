package droppriv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/bbockelm/golang-htcondor/config"
)

const (
	defaultCondorUser   = "condor"
	configKeyDropPriv   = "DROP_PRIVILEGES"
	configKeyCondorIDs  = "CONDOR_IDS"
	configKeyCondorUser = "CONDOR_USER"
)

// Identity represents a resolved Unix user and group.
type Identity struct {
	UID  uint32
	GID  uint32
	Name string
}

// Config controls how the drop privileges manager behaves.
type Config struct {
	Enabled    bool
	CondorUser string
	CondorIDs  *Identity
}

// Manager coordinates per-thread privilege transitions for filesystem access.
type Manager struct {
	enabled          bool
	defaultIdentity  Identity
	originalIdentity Identity
	cacheMu          sync.Mutex
	cachedIdentities map[string]Identity
}

var defaultManager atomic.Pointer[Manager]

// DefaultManager returns the singleton manager built from the default HTCondor configuration.
func DefaultManager() *Manager {
	if mgr := defaultManager.Load(); mgr != nil {
		return mgr
	}

	mgr := loadDefaultManager()
	defaultManager.Store(mgr)
	return mgr
}

// ReloadDefaultManager forces the default manager to be rebuilt using the current HTCondor configuration.
func ReloadDefaultManager() {
	defaultManager.Store(loadDefaultManager())
}

func loadDefaultManager() *Manager {
	conf := Config{CondorUser: defaultCondorUser}
	if cfg, err := config.New(); err == nil {
		conf = ConfigFromHTCondor(cfg)
	}

	mgr, err := NewManager(conf)
	if err == nil {
		return mgr
	}

	fallback, fallbackErr := NewManager(Config{CondorUser: conf.CondorUser})
	if fallbackErr == nil {
		return fallback
	}

	lastResort, lastErr := NewManager(Config{})
	if lastErr == nil {
		return lastResort
	}

	//nolint:gosec // G115 - os.Geteuid/Getegid are system UIDs; for Linux and Mac, these are uint32.
	return &Manager{enabled: false, defaultIdentity: Identity{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}, cachedIdentities: make(map[string]Identity)}
}

// ConfigFromHTCondor builds a Config using the HTCondor configuration parameters.
// DROP_PRIVILEGES toggles the feature on/off. CONDOR_IDS overrides the condor UID/GID.
// CONDOR_USER overrides the condor username lookup.
func ConfigFromHTCondor(cfg *config.Config) Config {
	conf := Config{CondorUser: defaultCondorUser}
	if cfg == nil {
		return conf
	}

	if rawEnabled, ok := cfg.Get(configKeyDropPriv); ok {
		conf.Enabled = isTruthy(rawEnabled)
	}

	if ids, ok := cfg.Get(configKeyCondorIDs); ok {
		if parsed, err := parseIDPair(ids); err == nil {
			conf.CondorIDs = &parsed
		}
	}

	if userName, ok := cfg.Get(configKeyCondorUser); ok && strings.TrimSpace(userName) != "" {
		conf.CondorUser = strings.TrimSpace(userName)
	}

	return conf
}

// NewManager constructs a Manager from the provided configuration.
// Call Start() to drop privileges if enabled.
func NewManager(conf Config) (*Manager, error) {
	if conf.CondorUser == "" {
		conf.CondorUser = defaultCondorUser
	}

	identity, err := resolveDefaultIdentity(conf)
	if err != nil {
		return nil, err
	}

	// Capture original identity
	original, err := currentIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed to get current identity: %w", err)
	}

	mgr := &Manager{
		enabled:          conf.Enabled,
		defaultIdentity:  identity,
		originalIdentity: original,
		cachedIdentities: make(map[string]Identity),
	}

	return mgr, nil
}

// Start drops the manager's effective privileges to the condor user if enabled.
func (m *Manager) Start() error {
	if !m.enabled {
		return nil
	}

	if err := dropPrivileges(m.defaultIdentity); err != nil {
		return fmt.Errorf("failed to drop privileges: %w", err)
	}

	return nil
}

// Stop restores the manager's original privileges if it was started with privileges dropped.
func (m *Manager) Stop() error {
	if !m.enabled {
		return nil
	}

	if err := restorePrivileges(m.originalIdentity); err != nil {
		return fmt.Errorf("failed to restore privileges: %w", err)
	}

	return nil
}

func resolveDefaultIdentity(conf Config) (Identity, error) {
	if conf.CondorIDs != nil {
		id := *conf.CondorIDs
		if id.Name == "" {
			id.Name = conf.CondorUser
		}
		return id, nil
	}

	if conf.CondorUser != "" {
		if id, err := lookupUser(conf.CondorUser); err == nil {
			return id, nil
		}
	}

	return currentIdentity()
}

func (m *Manager) resolveUser(userName string) (Identity, error) {
	if strings.TrimSpace(userName) == "" {
		return m.defaultIdentity, nil
	}

	m.cacheMu.Lock()
	if cached, ok := m.cachedIdentities[userName]; ok {
		m.cacheMu.Unlock()
		return cached, nil
	}
	m.cacheMu.Unlock()

	id, err := lookupUser(userName)
	if err != nil {
		return Identity{}, err
	}

	m.cacheMu.Lock()
	m.cachedIdentities[userName] = id
	m.cacheMu.Unlock()

	return id, nil
}

func lookupUser(userName string) (Identity, error) {
	// Try using the new lookup system
	if userInfo, err := LookupUser(context.Background(), userName); err == nil {
		return Identity{
			UID:  userInfo.UID,
			GID:  userInfo.GID,
			Name: userInfo.Username,
		}, nil
	}

	return Identity{}, fmt.Errorf("unable to resolve user %q", userName)
}

func currentIdentity() (Identity, error) {
	//nolint:gosec // G115 - os.Geteuid/Getegid are system UIDs, conversion to uint32 is safe
	uid := uint32(os.Geteuid())
	//nolint:gosec // G115 - os.Geteuid/Getegid are system UIDs, conversion to uint32 is safe
	gid := uint32(os.Getegid())

	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}

	return Identity{UID: uid, GID: gid, Name: name}, nil
}

func parseIDPair(ids string) (Identity, error) {
	parts := strings.Split(strings.TrimSpace(ids), ":")
	if len(parts) != 2 {
		return Identity{}, fmt.Errorf("expected uid:gid format, got %q", ids)
	}
	uid, err := parseUint32(strings.TrimSpace(parts[0]))
	if err != nil {
		return Identity{}, err
	}
	gid, err := parseUint32(strings.TrimSpace(parts[1]))
	if err != nil {
		return Identity{}, err
	}
	return Identity{UID: uid, GID: gid}, nil
}

func parseUint32(val string) (uint32, error) {
	parsed, err := strconv.ParseUint(val, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value %q: %w", val, err)
	}
	return uint32(parsed), nil
}

func isTruthy(val string) bool {
	v := strings.TrimSpace(strings.ToLower(val))
	switch v {
	case "1", "true", "t", "yes", "y", "on":
		return true
	case "0", "false", "f", "no", "n", "off", "":
		return false
	default:
		return false
	}
}

// ErrUnsupported is returned when privilege dropping is not supported on the current platform.
var ErrUnsupported = errors.New("drop privileges not supported on this platform")
