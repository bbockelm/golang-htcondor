package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/metricsd"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/interactive"
	"github.com/bbockelm/golang-htcondor/webapi/jobwatch"
	"github.com/bbockelm/golang-htcondor/webapi/matchanalyzer"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
	"github.com/bbockelm/golang-htcondor/webapi/skills"
	"github.com/bbockelm/golang-htcondor/webapi/submitpolicy"
)

// Server represents the MCP server
type Server struct {
	schedd *htcondor.Schedd
	// scheddProvider, when set, is consulted for every schedd call
	// instead of the snapshot above. The HTTP server replaces its
	// schedd handle when the collector reports a new address, and a
	// copy of the old pointer keeps dialling a socket that no longer
	// exists -- see getSchedd.
	scheddProvider func() *htcondor.Schedd
	collector      *htcondor.Collector
	credd          htcondor.CreddClient
	// creddProvider, when set, is consulted for every credd use instead
	// of the snapshot above. An access point often discovers its credd
	// after this server is built, and a snapshot taken then stays nil
	// forever -- which withholds the credential tools entirely, since the
	// catalogue offers them only when a credd is present. See getCredd.
	creddProvider func() htcondor.CreddClient
	// instructions is the built initialize-response text. It is swapped
	// atomically because SetInstructions can run on a reconfigure while
	// an initialize is being served.
	instructions atomic.Pointer[string]
	// customInstructions is the operator's MCP_INSTRUCTIONS text, kept so
	// the initialize text can be rebuilt when the skills library changes
	// without the operator having to set it again.
	customInstructions atomic.Pointer[string]
	// disabledTools is the operator's HTTP_API_MCP_DISABLED_TOOLS matcher. Swapped
	// atomically because a reconfigure can install a new one while a
	// tools/list or a tool call is being served.
	disabledTools atomic.Pointer[disabledToolMatcher]
	// catalogGen counts changes to what a caller would be served -- the
	// instructions and the tool catalogue built beside them. The SDK
	// transport caches a server per scope set, and this is how those
	// caches learn they are stale.
	catalogGen atomic.Uint64
	// skills is the site-authored skill library. Swapped atomically: a
	// reconfigure or the reload poll replaces it from disk while requests
	// are reading.
	skills atomic.Pointer[skills.Library]
	// skillsDir is where that library is read from, kept so the reload
	// poll knows what to look at. Atomic because a reconfigure can change
	// it while the poll is running.
	skillsDir atomic.Pointer[string]
	// skillsStop halts the reload poll; nil when none was started.
	skillsStop     chan struct{}
	skillsStopOnce sync.Once
	signingKeyPath string
	// shareSigner mints the signed upload URLs create_input_upload_url
	// hands back. Derived from the pool signing key so the URL verifies
	// in the REST daemon that will redeem it -- which is the whole point
	// when this server is the standalone stdio one with no listener.
	// nil when no signing key is configured.
	shareSigner        *shareurl.Signer
	trustDomain        string
	uidDomain          string
	httpBaseURL        string // Base URL for HTTP API (e.g., "http://localhost:8080") for file download links
	logger             *logging.Logger
	metricsRegistry    *metricsd.Registry
	prometheusExporter *metricsd.PrometheusExporter
	delegated          bool
	submitPolicy       submitpolicy.Policy
	// dagmanPath is the access point's condor_dagman binary. See
	// Config.DagmanPath.
	dagmanPath string
	// dagmanEnv is extra environment for the DAGMan manager job. See
	// Config.DagmanEnvironment.
	dagmanEnv map[string]string
	// dagmanLayoutOnce memoises what the schedd's own configuration says
	// about its DAGMan installation, so a workflow submission costs at
	// most one extra DC_CONFIG_VAL round trip per process. It is never
	// refreshed: an access point that moves its binaries is restarting
	// its daemons anyway. See Server.dagmanLayout.
	dagmanLayoutOnce   sync.Once
	dagmanLayoutBin    string
	dagmanLayoutNoPort bool
	// dagmanLayoutFn replaces that discovery, so the precedence between
	// configuration, discovery and the package default can be tested
	// without a schedd. nil uses discoverDagmanLayout.
	dagmanLayoutFn func(context.Context) (string, bool)
	stdin          io.Reader
	stdout         io.Writer
	// matchAnalysisOnce / matchAnalysisSlots back the lazy-allocated
	// CollectorSlotProvider used by the analyze_job_match tool. Same
	// motivation as the httpserver Handler equivalent: keep the slot
	// cache alive across calls so a debug session that re-runs analysis
	// only triggers one collector query per cache window.
	matchAnalysisOnce  sync.Once
	matchAnalysisSlots *matchanalyzer.CollectorSlotProvider

	// adminUsers is the set of subjects (JWT `sub` values) treated
	// as administrators. Admin users skip the per-tool owner-scope
	// wrapper that otherwise forces every query / mutation to be
	// limited to the caller's own jobs. Configured via
	// Config.AdminUsers; nil/empty means no admin users (default —
	// every authenticated caller is treated as a normal user).
	adminUsers map[string]struct{}

	// ccbDialer decides how to reach a daemon behind a Condor Connection
	// Broker. An API server that cannot accept inbound connections needs
	// one; see HandlerConfig.CCB, which is where the operator sets it
	// once for every surface.
	ccbDialer *htcondor.CCBDialer

	// htcondorConfig is the ambient HTCondor configuration, used to build the CLIENT security
	// config when dialing the htcondordb database for the DB-backed tools. nil disables them.
	htcondorConfig *config.Config
	// dbMirror discovers and dials the synchronized htcondordb mirror, and owns the
	// policy for when a read may be served from it (webapi/dbmirror). Shared with the
	// REST API so both surfaces route on the same freshness rules.
	dbMirror     *dbmirror.Locator
	jobWatch     *jobwatch.Store
	jobWatchEval *jobwatch.Evaluator
	watchMaxWait time.Duration

	// build carries the site's container-build configuration, resolved
	// from Config at construction so the tool does not reach back into
	// a Config the server does not keep.
	build buildSettings

	// interactive owns the caller's named interactive sessions: the
	// jobs behind them, their leases, and the SSH connections commands
	// run over. One per server, because a session outlives the call
	// that created it -- and, under a sessionless transport, the
	// connection too.
	interactive *interactive.Manager
}

// Config holds server configuration
type Config struct {
	ScheddName string // Schedd name
	ScheddAddr string // Schedd address (e.g., "127.0.0.1:9618"). If empty, discovered from collector.
	// ScheddHost is the SCHEDD_HOST setting: the host (optionally
	// "name@host", optionally with a port) whose schedd this server
	// should talk to. Consulted when neither ScheddAddr nor ScheddName
	// is set, and it selects that host's schedd rather than whichever
	// one the collector lists first.
	ScheddHost string
	Schedd     *htcondor.Schedd // Pre-configured Schedd instance (optional, if provided, ScheddName/ScheddAddr are ignored)

	// ScheddProvider returns the schedd to use for each call. Prefer it
	// over Schedd when the address can change under you: a schedd that
	// restarts comes back on a different shared-port socket, and a
	// handle captured once then points at nothing.
	ScheddProvider func() *htcondor.Schedd
	SigningKeyPath string               // Path to token signing key (optional, for token generation)
	TrustDomain    string               // Trust domain for token issuer (optional)
	UIDDomain      string               // UID domain for generated token username (optional)
	HTTPBaseURL    string               // Base URL for HTTP API (e.g., "http://localhost:8080") for file download links
	Collector      *htcondor.Collector  // Collector for metrics and discovery (optional)
	Credd          htcondor.CreddClient // Optional credd client for credential management
	// CreddProvider returns the credd to use for each call. Prefer it
	// over Credd whenever the credd can appear or move after this server
	// is built: an access point often discovers its credd after startup,
	// and a handle captured at construction stays nil forever -- which
	// silently withholds the credential tools, since the catalogue only
	// offers them when a credd is present.
	CreddProvider func() htcondor.CreddClient
	Instructions  string // Server-level instructions provided to all agents in the MCP initialize response
	// DisabledTools (HTTP_API_MCP_DISABLED_TOOLS) names tools this site cannot
	// offer, as path.Match patterns separated by commas or whitespace.
	// See disabled_tools.go.
	DisabledTools string
	// SkillsReloadInterval is how often to re-read SkillsDir so a checkout
	// updated underneath this process is noticed without a reconfigure.
	// Zero disables the poll, leaving reloads to reconfigure alone. The
	// check is stat-only until something actually changes, so a short
	// interval is cheap.
	SkillsReloadInterval time.Duration
	// SkillsDir is a directory of site-authored Markdown skills to publish
	// to agents. Empty disables the feature.
	SkillsDir       string
	EnableMetrics   bool            // Enable metrics collection (default: true if Collector is set)
	MetricsCacheTTL time.Duration   // Metrics cache TTL (default: 10s)
	Logger          *logging.Logger // Logger instance (optional, creates default if nil)
	Stdin           io.Reader       // Input stream (default: os.Stdin)
	Stdout          io.Writer       // Output stream (default: os.Stdout)
	// AdminUsers is the list of authenticated subjects (JWT `sub` /
	// authenticated username) who get admin treatment in tool
	// dispatch — most importantly, they are exempt from the
	// per-tool owner-scope wrapper that otherwise restricts queries
	// and mutations to the caller's own jobs. Match must be exact
	// against the value returned by
	// htcondor.GetAuthenticatedUserFromContext (typically
	// "user@uid.domain"). Empty list = no admin users (default).
	AdminUsers []string

	// HTCondorConfig is the ambient HTCondor configuration. When set (together with a
	// Collector), the htcondordb-backed tools are enabled: the server discovers the database
	// via the collector and authenticates to it using this config's SEC_* knobs. nil disables
	// those tools.
	HTCondorConfig *config.Config

	// Delegated marks a server that acts on behalf of remote callers
	// rather than running as the user, which is the case when webapi
	// embeds it behind HTTP. It changes what an unknown caller means:
	// a delegated server must refuse an owner-scoped tool it cannot
	// confine, while a server run from a user's shell over stdio is
	// already confined by being that user's process. Default false, so
	// the stdio CLI keeps working exactly as before.
	Delegated bool

	// htcondordb mirror routing, mirroring the REST handler's config of
	// the same name so one daemon routes both surfaces identically. See
	// dbmirror.Options.
	DBMirrorName     string // HTTP_API_DBMIRROR_NAME
	DBMirrorAddress  string // HTTP_API_DBMIRROR_ADDRESS
	DBMirrorRequired bool   // HTTP_API_DBMIRROR_REQUIRED
	// JobWatch and JobWatchEval enable the watch tools. Both or neither:
	// registering a watch nothing evaluates would be a promise the
	// server cannot keep, and the agent would wait forever.
	JobWatch     *jobwatch.Store
	JobWatchEval *jobwatch.Evaluator

	// WatchMaxWait caps how long watch_jobs may block in-call before
	// returning (HTTP_API_MCP_WATCH_MAX_WAIT). It must stay under the
	// gateway/connector timeout in front of this server: a block that
	// outlives it loses the response carrying the watch id. Zero or
	// negative uses the built-in MaxWaitSeconds default.
	WatchMaxWait time.Duration

	// DBMirror lets a host that already has a Locator share it instead
	// of having a second one built from the three knobs above. The HTTP
	// daemon does: it runs these tools in-process, and two Locators
	// would mean two discovery caches, two sets of poll timings, and an
	// admin page describing only one of them. Nil (the standalone
	// stdio server) builds a Locator from the knobs.
	DBMirror *dbmirror.Locator

	// SubmitPolicy is the operator's site-wide submit-file defaults and
	// overrides. The agent surface gets the same treatment as the REST
	// and web surfaces: a site requirement an agent cannot know about is
	// exactly the kind this exists to satisfy.
	SubmitPolicy submitpolicy.Policy

	// CCB decides how to reach a daemon behind a Condor Connection
	// Broker. Same setting the REST surface uses (HandlerConfig.CCB),
	// and it applies to everything here that reaches a daemon behind
	// CCB: an interactive session's shell, and tailing a running job
	// through its starter. An API server that cannot accept inbound
	// connections needs it for both.
	CCB *htcondor.CCBDialer
	// InteractiveRequirements is the operator's interactive-job
	// Requirements expression (HTTP_API_INTERACTIVE_REQUIREMENTS). The
	// REST terminal applies it; sessions are the same kind of job on the
	// same pool and must not be able to land where it excludes.
	InteractiveRequirements string

	// InteractiveExtraSubmit is the operator's interactive-specific
	// submit-file block (HTTP_API_INTERACTIVE_EXTRA_SUBMIT), applied to
	// interactive session jobs on top of SubmitPolicy. The REST
	// terminal already honours it; an agent's session is the same kind
	// of job on the same pool and gets the same treatment.
	InteractiveExtraSubmit string

	// Build carries the site's container-build configuration for the
	// build_container tool. A pool's build machines are selected by site
	// convention -- CHTC uses +IsBuildJob = True, which a schedd
	// transform then turns into the real slot requirements -- and no
	// agent can be expected to know that convention.
	Build BuildConfig

	// DagmanPath is where condor_dagman lives on the access point
	// (HTTP_API_DAGMAN_PATH). condor_submit_dag finds this with which()
	// on the submitting machine, which is no help here: this server
	// submits to a schedd it shares no filesystem with, so the path has
	// to be configured. Empty uses dagman.DefaultDagmanPath.
	DagmanPath string

	// DagmanEnvironment is extra environment for the DAGMan manager job
	// (HTTP_API_DAGMAN_ENVIRONMENT), as KEY=VALUE pairs. Needed by an
	// access point whose configuration is not in the default place: the
	// schedd hands a scheduler-universe job only what its ad carries, and
	// getenv is no help because it would capture THIS server's
	// environment rather than the access point's.
	DagmanEnvironment map[string]string
}

// NewServer creates a new MCP server
func NewServer(cfg Config) (*Server, error) {
	// Initialize logger if not provided
	logger := cfg.Logger
	if logger == nil {
		var err error
		logger, err = logging.New(&logging.Config{
			OutputPath: "stderr",
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create logger: %w", err)
		}
	}

	// Use provided schedd or create new one
	var schedd *htcondor.Schedd
	switch {
	case cfg.ScheddProvider != nil:
		// A provider supersedes any snapshot: it is consulted per call,
		// so it also answers "was a schedd supplied" here. Falling
		// through to discovery instead would fail for a caller that
		// supplied a provider and no address.
		logger.Debug(logging.DestinationSchedd, "Using provided schedd getter")
		schedd = cfg.ScheddProvider()
	case cfg.Schedd != nil:
		// Reuse provided schedd instance
		logger.Debug(logging.DestinationSchedd, "Using provided schedd instance")
		schedd = cfg.Schedd
	default:
		// Discover schedd address if not provided
		scheddAddr := cfg.ScheddAddr
		if scheddAddr == "" {
			if cfg.Collector == nil {
				return nil, fmt.Errorf("ScheddAddr not provided and Collector not configured for discovery")
			}

			logger.Infof(logging.DestinationSchedd, "ScheddAddr not provided, discovering schedd '%s' from collector...", cfg.ScheddName)
			var err error
			scheddAddr, err = discoverSchedd(cfg.Collector, cfg.ScheddName, cfg.ScheddHost, 10*time.Second, logger)
			if err != nil {
				return nil, fmt.Errorf("failed to discover schedd: %w", err)
			}
			logger.Info(logging.DestinationSchedd, "Discovered schedd", "address", scheddAddr)
		}

		// Create schedd with the address as-is (can be host:port or sinful string)
		schedd = htcondor.NewSchedd(cfg.ScheddName, scheddAddr)
	}

	// Default I/O streams
	stdin := cfg.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	stdout := cfg.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}

	adminUsers := make(map[string]struct{}, len(cfg.AdminUsers))
	for _, u := range cfg.AdminUsers {
		u = strings.TrimSpace(u)
		if u != "" {
			adminUsers[u] = struct{}{}
		}
	}

	s := &Server{
		schedd:         schedd,
		scheddProvider: cfg.ScheddProvider,
		collector:      cfg.Collector,
		credd:          cfg.Credd,
		creddProvider:  cfg.CreddProvider,
		trustDomain:    cfg.TrustDomain,
		uidDomain:      cfg.UIDDomain,
		signingKeyPath: cfg.SigningKeyPath,
		httpBaseURL:    cfg.HTTPBaseURL,
		logger:         logger,
		stdin:          stdin,
		stdout:         stdout,
		adminUsers:     adminUsers,
		htcondorConfig: cfg.HTCondorConfig,
		ccbDialer:      cfg.CCB,
		delegated:      cfg.Delegated,
		submitPolicy:   cfg.SubmitPolicy,
		dagmanPath:     cfg.DagmanPath,
		dagmanEnv:      cfg.DagmanEnvironment,
		dbMirror:       cfg.DBMirror,
		jobWatch:       cfg.JobWatch,
		jobWatchEval:   cfg.JobWatchEval,
		watchMaxWait:   cfg.WatchMaxWait,
		build:          buildSettingsFromConfig(cfg),
	}
	// A missing or unreadable signing key is not fatal: it disables the
	// one tool that needs it, and that tool says so when called.
	if key, err := shareurl.KeyFromSigningKeyFile(cfg.SigningKeyPath); err == nil {
		if signer, serr := shareurl.NewSigner(key); serr == nil {
			s.shareSigner = signer
		}
	} else if cfg.SigningKeyPath != "" {
		logger.Warn(logging.DestinationMCP,
			"Could not derive the share-URL key; upload URLs are unavailable",
			"signing_key", cfg.SigningKeyPath, "error", err)
	}

	// Load before the instructions are built: the initialize text names the
	// skills, so building it first would advertise an empty library.
	if dir := strings.TrimSpace(cfg.SkillsDir); dir != "" {
		s.SetSkillsDir(dir)
		if s.startSkillsReload(cfg.SkillsReloadInterval) {
			logger.Info(logging.DestinationMCP, "Polling the site skills directory for changes",
				"dir", dir, "interval", cfg.SkillsReloadInterval.String())
		}
	}
	s.SetDisabledTools(cfg.DisabledTools)
	s.SetInstructions(cfg.Instructions)
	if s.dbMirror == nil {
		s.dbMirror = dbmirror.NewLocatorWithOptions(cfg.Collector, cfg.HTCondorConfig, dbmirror.Options{
			Name:     cfg.DBMirrorName,
			Address:  cfg.DBMirrorAddress,
			Required: cfg.DBMirrorRequired,
			// Which schedd this daemon serves, so discovery can tell
			// this access point's mirror from another's.
			ScheddAddress: schedd.Address,
		})
	}

	// Interactive sessions. The manager holds a schedd accessor rather
	// than the schedd itself so it follows any later rediscovery, and
	// it is created unconditionally: an access point that cannot run
	// condor_ssh_to_job reports that per call, which is a better
	// answer than a tool that silently does not exist.
	interactiveMgr, err := interactive.NewManager(interactive.Options{
		// getSchedd, not the s.schedd snapshot: this server replaces its
		// schedd when the collector reports a new address, and holding
		// the old pointer is how MCP kept dialling a socket that no
		// longer existed. The accessor is why this is a function.
		Schedd:       func() interactive.ScheddClient { return s.getSchedd() },
		Logger:       logger,
		LogDest:      logging.DestinationMCP,
		SubmitPolicy: cfg.SubmitPolicy,
		ExtraSubmit:  cfg.InteractiveExtraSubmit,
		CCB:          cfg.CCB,
		Requirements: cfg.InteractiveRequirements,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create interactive session manager: %w", err)
	}
	s.interactive = interactiveMgr

	// Setup metrics if collector is provided
	enableMetrics := cfg.EnableMetrics
	if cfg.Collector != nil && !cfg.EnableMetrics {
		enableMetrics = true // Enable by default if collector is provided
	}

	if enableMetrics && cfg.Collector != nil {
		// Create metrics registry and Prometheus exporter
		s.metricsRegistry = metricsd.NewRegistry()
		s.prometheusExporter = metricsd.NewPrometheusExporter(s.metricsRegistry)

		// Note: In MCP server, metrics collection is passive
		// The HTTP server would start the collector, but here we just make it available
		// cacheTTL from cfg.MetricsCacheTTL would be used if we implement background collection
	}

	return s, nil
}

// Close releases what this server holds open beyond a single call: the
// interactive sessions' SSH connections and their heartbeat goroutines,
// and the goroutine polling the site skills directory.
//
// It deliberately leaves the session JOBS running. A daemon restart
// should find them and re-adopt them, which is the property that makes
// a named session usable across a restart at all; the in-job watchdog
// is what reclaims a session whose server never comes back.
func (s *Server) Close() {
	if s == nil {
		return
	}
	s.stopSkillsReload()
	if s.interactive == nil {
		return
	}
	s.interactive.Close()
}

// discoverSchedd discovers a schedd from the collector
func discoverSchedd(collector *htcondor.Collector, scheddName, scheddHost string, timeout time.Duration, _ *logging.Logger) (string, error) {
	// A SCHEDD_HOST carrying a port is already an address; nothing to
	// look up.
	target := htcondor.ParseScheddHost(scheddHost)
	if scheddName == "" && target.Address() != "" {
		return target.Address(), nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	constraint := "true"
	switch {
	case scheddName != "":
		constraint = fmt.Sprintf("Name == %q", scheddName)
	case target.IsSet():
		constraint = target.CollectorConstraint()
	}

	ads, _, err := collector.QueryAdsWithOptions(ctx, "ScheddAd", constraint, nil)
	if err != nil {
		return "", fmt.Errorf("collector query failed: %w", err)
	}

	if len(ads) == 0 {
		switch {
		case scheddName != "":
			return "", fmt.Errorf("schedd '%s' not found in collector", scheddName)
		case target.IsSet():
			return "", fmt.Errorf("no schedd for SCHEDD_HOST %q found in collector", scheddHost)
		}
		return "", fmt.Errorf("no schedds found in collector")
	}

	// Extract MyAddress from the first matching schedd
	myAddr, ok := ads[0].EvaluateAttrString("MyAddress")
	if !ok {
		return "", fmt.Errorf("schedd ad missing MyAddress attribute")
	}

	return myAddr, nil
}

// MCPMessage represents an MCP protocol message
type MCPMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *MCPError       `json:"error,omitempty"`
}

// MCPError represents an MCP error
type MCPError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Run starts the MCP server and processes messages
func (s *Server) Run(ctx context.Context) error {
	s.logger.Info(logging.DestinationGeneral, "Starting MCP server")

	decoder := json.NewDecoder(s.stdin)
	encoder := json.NewEncoder(s.stdout)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info(logging.DestinationGeneral, "MCP server shutting down")
			return nil
		default:
		}

		var msg MCPMessage
		if err := decoder.Decode(&msg); err != nil {
			if err == io.EOF {
				s.logger.Info(logging.DestinationGeneral, "MCP server: client disconnected")
				return nil
			}
			s.logger.Error(logging.DestinationGeneral, "Failed to decode message", "error", err)
			continue
		}

		s.logger.Debug(logging.DestinationGeneral, "Received MCP message", "method", msg.Method, "id", msg.ID)

		// Handle the message
		response := s.handleMessage(ctx, &msg)

		// Send response
		if err := encoder.Encode(response); err != nil {
			s.logger.Error(logging.DestinationGeneral, "Failed to encode response", "error", err)
			continue
		}
	}
}

// handleMessage processes an MCP message and returns a response
func (s *Server) handleMessage(ctx context.Context, msg *MCPMessage) *MCPMessage {
	// Always set JSONRPC version
	response := &MCPMessage{
		JSONRPC: "2.0",
		ID:      msg.ID,
	}

	// Handle different methods
	switch msg.Method {
	case "initialize":
		response.Result = s.handleInitialize(ctx, msg.Params)
	case "tools/list":
		response.Result = s.handleListTools(ctx, msg.Params)
	case "tools/call":
		// Minted here, not inside handleCallTool: the id has to be
		// readable on THIS scope so the error result can carry the same
		// value the log line does. A context derived inside the callee
		// does not come back.
		traceID := newTraceID()
		ctx = withTraceID(ctx, traceID)
		result, err := s.handleCallTool(ctx, msg.Params)
		switch {
		case err == nil:
			response.Result = result
		case isProtocolError(err):
			// A malformed request: no tool ran, so there is no tool
			// result to return.
			response.Error = &MCPError{
				Code:    -32000,
				Message: err.Error(),
			}
		default:
			// A tool ran and failed. MCP wants that as a normal result
			// carrying isError, because a JSON-RPC error is a protocol
			// fault that clients surface as an opaque failure -- the
			// model never sees the text, so the diagnosis is thrown
			// away exactly when it is needed.
			response.Result = toolErrorResult(toolNameFromParams(msg.Params), traceID, err)
		}
	case "resources/list":
		response.Result = s.handleListResources(ctx, msg.Params)
	case "resources/read":
		result, err := s.handleReadResource(ctx, msg.Params)
		if err != nil {
			response.Error = &MCPError{
				Code:    -32000,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}
	default:
		response.Error = &MCPError{
			Code:    -32601,
			Message: fmt.Sprintf("Method not found: %s", msg.Method),
		}
	}

	return response
}

// HandleMessage is the public interface for handling MCP messages (used by HTTP handler)
func (s *Server) HandleMessage(ctx context.Context, msg *MCPMessage) *MCPMessage {
	return s.handleMessage(ctx, msg)
}

// SetStdin sets the input stream for the MCP server and returns the previous stream
func (s *Server) SetStdin(stdin io.Reader) io.Reader {
	old := s.stdin
	s.stdin = stdin
	return old
}

// SetStdout sets the output stream for the MCP server and returns the previous stream
func (s *Server) SetStdout(stdout io.Writer) io.Writer {
	old := s.stdout
	s.stdout = stdout
	return old
}

// handleInitialize handles the initialize request
func (s *Server) handleInitialize(_ context.Context, _ json.RawMessage) interface{} {
	result := map[string]interface{}{
		"protocolVersion": "2024-11-05",
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{},
			"resources": map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "htcondor-mcp",
			"version": "0.1.0",
		},
	}
	if v := s.instructions.Load(); v != nil && *v != "" {
		s.logger.Info(logging.DestinationMCP, "Including instructions in initialize response", "length", len(*v))
		result["instructions"] = *v
	}
	return result
}

// toolNameFromParams re-reads just the tool name from a tools/call
// params blob, for error reporting. The dispatcher has already parsed
// and validated these params by the time we need this, so a failure here
// means the name is genuinely absent rather than malformed.
func toolNameFromParams(params json.RawMessage) string {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &req); err != nil || req.Name == "" {
		return "unknown"
	}
	return req.Name
}

// getSchedd returns the schedd to use for this call.
//
// The HTTP server replaces its schedd handle when the collector reports a
// new address -- which happens whenever the schedd restarts, since that
// changes its shared-port socket. Reading through the provider each time
// is what keeps MCP from holding the handle that was correct at startup
// and dialling a dead socket forever after.
// getCredd returns the credd to use for this call: the provider's
// answer when there is one, else the snapshot given at construction.
// nil means this deployment has no credd, which is a normal state and
// not an error.
func (s *Server) getCredd() htcondor.CreddClient {
	if s.creddProvider != nil {
		if c := s.creddProvider(); c != nil {
			return c
		}
	}
	return s.credd
}

func (s *Server) getSchedd() *htcondor.Schedd {
	if s.scheddProvider != nil {
		if sc := s.scheddProvider(); sc != nil {
			return sc
		}
	}
	return s.schedd
}
