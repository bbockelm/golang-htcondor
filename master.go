package htcondor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
)

// DC command identifiers used by the master for daemon lifecycle signaling.
const (
	DCChildAlive = 60008 // DC_CHILDALIVE: child keepalive to parent
	DCSetReady   = 60043 // DC_SET_READY: daemon signals startup readiness
	DCQueryReady = 60044 // DC_QUERY_READY: master readiness query (reserved for future use)
)

const (
	defaultHangTimeout = 10 * time.Minute
)

// Master provides child-to-master control plane helpers for daemons launched by condor_master.
// It can send keepalive heartbeats and readiness notifications.
type Master struct {
	address    string
	daemonName string
	parentPID  int
	sender     masterSender
}

// KeepAliveOptions controls keepalive payload and timing.
type KeepAliveOptions struct {
	// HangTimeout is the grace period the master should allow before considering the daemon hung.
	HangTimeout time.Duration
	// Interval is how frequently to send keepalives. If zero, it is derived from HangTimeout.
	Interval time.Duration
	// DprintfLockDelay optionally reports the log lock hold time; omitted when zero.
	DprintfLockDelay time.Duration
}

// ReadyOptions customizes the ready-state notification.
type ReadyOptions struct {
	// State is a human-readable daemon state. Defaults to "Ready".
	State string
	// Name overrides the daemon name. If empty, Master.daemonName is used.
	Name string
	// Attributes adds custom ClassAd attributes to the readiness ping.
	Attributes map[string]any
}

type keepAliveRequest struct {
	Address          string
	PID              int
	HangTimeout      time.Duration
	DprintfLockDelay time.Duration
}

type readyRequest struct {
	Address    string
	PID        int
	Name       string
	State      string
	Attributes map[string]any
}

type masterSender interface {
	sendKeepAlive(ctx context.Context, req keepAliveRequest) error
	sendReady(ctx context.Context, req readyRequest) error
}

// NewMaster constructs a Master pointed at a specific command address.
func NewMaster(address string) *Master {
	return &Master{
		address: address,
		sender:  &cedarMasterSender{},
	}
}

// MasterFromEnv builds a Master using HTCondor's CONDOR_INHERIT metadata.
// It expects the CONDOR_INHERIT environment variable to contain the parent PID
// followed by the master's command sinful string (e.g., "1234 <127.0.0.1:9618>").
//
// As a side effect, this also primes the global cedar SessionCache by
// touching it once: GetSessionCache() lazily imports inherited sessions
// from CONDOR_PRIVATE_INHERIT, and we want that import to happen at
// daemon startup rather than the first time we send DC_CHILDALIVE.
// Without the priming, a transient init race could cause our first
// keepalive to do a fresh handshake when an inherited family session
// was available all along — the master would then log
// `vscode@<host>` for that one DC_CHILDALIVE instead of `condor@child`,
// which is benign but makes audit logs noisier.
func MasterFromEnv() (*Master, error) {
	inherit := os.Getenv("CONDOR_INHERIT")
	if inherit == "" {
		return nil, errors.New("CONDOR_INHERIT not set")
	}

	parentPID, address, err := parseCondorInherit(inherit)
	if err != nil {
		return nil, err
	}

	// Force-import the inherited session cache. The cedar package
	// guards this with sync.Once, so calling it again later is a
	// no-op — we just want the import to happen here, deterministically.
	_ = security.GetSessionCache()

	return &Master{
		address:    address,
		daemonName: os.Getenv("_CONDOR_DAEMON_NAME"),
		parentPID:  parentPID,
		sender:     &cedarMasterSender{},
	}, nil
}

// Address returns the master's command address.
func (m *Master) Address() string {
	return m.address
}

// ParentPID returns the parent PID parsed from CONDOR_INHERIT when available.
func (m *Master) ParentPID() int {
	return m.parentPID
}

// DaemonName returns the configured daemon name (if provided).
func (m *Master) DaemonName() string {
	return m.daemonName
}

// SendKeepAlive transmits a DC_CHILDALIVE heartbeat to condor_master.
func (m *Master) SendKeepAlive(ctx context.Context, opts *KeepAliveOptions) error {
	if m.sender == nil {
		return errors.New("master sender not configured")
	}

	resolved := withKeepAliveDefaults(opts)
	req := keepAliveRequest{
		Address:          m.address,
		PID:              os.Getpid(),
		HangTimeout:      resolved.HangTimeout,
		DprintfLockDelay: resolved.DprintfLockDelay,
	}

	return m.sender.sendKeepAlive(ctx, req)
}

// StartKeepAlive launches a background keepalive loop. It sends an initial
// heartbeat immediately, then repeats at the configured interval until the
// context is cancelled or Stop is invoked.
//
// The returned stop function cancels the loop. The error channel is closed
// once the loop exits; non-nil errors are delivered through it.
func (m *Master) StartKeepAlive(ctx context.Context, opts *KeepAliveOptions) (stop func(), errs <-chan error, err error) {
	if m.sender == nil {
		return nil, nil, errors.New("master sender not configured")
	}

	resolved := withKeepAliveDefaults(opts)
	ctx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, 1)

	send := func() {
		if sendErr := m.sender.sendKeepAlive(ctx, keepAliveRequest{
			Address:          m.address,
			PID:              os.Getpid(),
			HangTimeout:      resolved.HangTimeout,
			DprintfLockDelay: resolved.DprintfLockDelay,
		}); sendErr != nil {
			select {
			case errCh <- sendErr:
			default:
			}
		}
	}

	// First send is synchronous so callers see immediate failures.
	if err := m.sender.sendKeepAlive(ctx, keepAliveRequest{
		Address:          m.address,
		PID:              os.Getpid(),
		HangTimeout:      resolved.HangTimeout,
		DprintfLockDelay: resolved.DprintfLockDelay,
	}); err != nil {
		cancel()
		close(errCh)
		return nil, nil, err
	}

	ticker := time.NewTicker(resolved.Interval)

	go func() {
		defer ticker.Stop()
		defer close(errCh)

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				send()
			}
		}
	}()

	return cancel, errCh, nil
}

// SendReady transmits a DC_SET_READY notification indicating the daemon
// successfully initialized and is ready to serve work.
func (m *Master) SendReady(ctx context.Context, opts *ReadyOptions) error {
	if m.sender == nil {
		return errors.New("master sender not configured")
	}

	resolved := withReadyDefaults(opts, m.daemonName)
	req := readyRequest{
		Address:    m.address,
		PID:        os.Getpid(),
		Name:       resolved.Name,
		State:      resolved.State,
		Attributes: resolved.Attributes,
	}

	return m.sender.sendReady(ctx, req)
}

func withKeepAliveDefaults(opts *KeepAliveOptions) KeepAliveOptions {
	resolved := KeepAliveOptions{}
	if opts != nil {
		resolved = *opts
	}

	if resolved.HangTimeout <= 0 {
		resolved.HangTimeout = defaultHangTimeout
	}
	if resolved.Interval <= 0 {
		resolved.Interval = computeKeepAliveInterval(resolved.HangTimeout)
	}
	return resolved
}

func withReadyDefaults(opts *ReadyOptions, daemonName string) ReadyOptions {
	resolved := ReadyOptions{}
	if opts != nil {
		resolved = *opts
	}

	if resolved.State == "" {
		resolved.State = "Ready"
	}
	if resolved.Name == "" {
		resolved.Name = daemonName
	}
	if resolved.Attributes == nil {
		resolved.Attributes = make(map[string]any)
	}
	return resolved
}

// condor keeps the child alive period as (timeout/3 - 30s) with a 1s floor.
func computeKeepAliveInterval(hangTimeout time.Duration) time.Duration {
	interval := hangTimeout/3 - 30*time.Second
	if interval < time.Second {
		interval = time.Second
	}
	return interval
}

func parseCondorInherit(value string) (int, string, error) {
	tokens := strings.Fields(value)
	if len(tokens) < 2 {
		return 0, "", fmt.Errorf("CONDOR_INHERIT format unexpected: %q", value)
	}

	pid, err := strconv.Atoi(tokens[0])
	if err != nil {
		return 0, "", fmt.Errorf("failed to parse parent pid from CONDOR_INHERIT: %w", err)
	}

	address := ""
	for _, token := range tokens[1:] {
		if strings.Contains(token, "<") && strings.Contains(token, ":") {
			address = token
			break
		}
	}
	if address == "" {
		address = tokens[1]
	}

	if address == "" {
		return 0, "", fmt.Errorf("failed to parse command address from CONDOR_INHERIT: %q", value)
	}

	return pid, address, nil
}

// cedarMasterSender implements the child->master control plane over CEDAR.
type cedarMasterSender struct{}

// hasInheritedSessionForCommand reports whether the global cedar
// session cache has an entry that resumes for the given (peer, command)
// pair. We use this to choose between SecurityNever (force resume,
// fail if no cached session) and SecurityRequired (full handshake) —
// the resumed path is what condor_master expects from a managed
// daemon, and it's the only way the master logs the child's
// authenticated identity as `condor@child` rather than the daemon
// process owner.
func hasInheritedSessionForCommand(peerAddr string, command int) bool {
	cache := security.GetSessionCache()
	if cache == nil {
		return false
	}
	cmdStr := strconv.Itoa(command)
	_, ok := cache.LookupByCommand("", peerAddr, cmdStr)
	return ok
}

// secConfigForMasterCommand builds the SecurityConfig for a child→
// master command. When an inherited session is cached for this peer
// and command, we set Authentication=NEVER to *demand* session
// resumption — the cedar Authenticator will then refuse to fall back
// to a full handshake on the same stream (which would advertise our
// own identity instead of the parent's). Without a cached session we
// drop back to the historical Authentication=REQUIRED path, which
// matches what callers got before this file learned about inherited
// sessions.
func secConfigForMasterCommand(ctx context.Context, command int, peerAddr string) (*security.SecurityConfig, error) {
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, command, "DAEMON", peerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}
	if hasInheritedSessionForCommand(peerAddr, command) {
		secConfig.Authentication = security.SecurityNever
	} else {
		secConfig.Authentication = security.SecurityRequired
	}
	return secConfig, nil
}

func (s *cedarMasterSender) sendKeepAlive(ctx context.Context, req keepAliveRequest) error {
	secConfig, err := secConfigForMasterCommand(ctx, DCChildAlive, req.Address)
	if err != nil {
		return err
	}

	htcondorClient, err := client.ConnectAndAuthenticate(ctx, req.Address, secConfig)
	if err != nil {
		return fmt.Errorf("failed to connect/authenticate to master at %s: %w", req.Address, err)
	}
	defer func() { _ = htcondorClient.Close() }()

	cedarStream := htcondorClient.GetStream()
	cedarStream.SetAuthenticated(true)

	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutInt(ctx, req.PID); err != nil {
		return fmt.Errorf("failed to serialize child pid: %w", err)
	}
	if err := msg.PutInt(ctx, int(req.HangTimeout/time.Second)); err != nil {
		return fmt.Errorf("failed to serialize hang timeout: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to send keepalive: %w", err)
	}

	return nil
}

func (s *cedarMasterSender) sendReady(ctx context.Context, req readyRequest) error {
	secConfig, err := secConfigForMasterCommand(ctx, DCSetReady, req.Address)
	if err != nil {
		return err
	}

	htcondorClient, err := client.ConnectAndAuthenticate(ctx, req.Address, secConfig)
	if err != nil {
		return fmt.Errorf("failed to connect/authenticate to master at %s: %w", req.Address, err)
	}
	defer func() { _ = htcondorClient.Close() }()

	cedarStream := htcondorClient.GetStream()
	cedarStream.SetAuthenticated(true)

	ad := classad.New()
	_ = ad.Set("DaemonPID", int64(req.PID))
	if req.Name != "" {
		_ = ad.Set("DaemonName", req.Name)
	}
	_ = ad.Set("DaemonState", req.State)
	for key, value := range req.Attributes {
		// Allow callers to override/extend attributes
		_ = ad.Set(key, value)
	}

	msg := message.NewMessageForStream(cedarStream)
	if err := msg.PutClassAd(ctx, ad); err != nil {
		return fmt.Errorf("failed to serialize ready ClassAd: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to send ready state: %w", err)
	}

	return nil
}
