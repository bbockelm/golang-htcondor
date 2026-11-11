package dagman

import (
	"context"
	"path"
	"strings"
	"sync"
)

// Layout is what an access point's own configuration says about its
// DAGMan installation: the directory its binaries are in, and whether
// DAGMan is configured to run without a command port.
//
// Both are properties of the machine a workflow is submitted TO, not of
// the machine this process runs on, which is why they are asked of the
// schedd rather than read locally -- and why discovering them is what
// makes a tarball or relocated install work without an operator setting
// HTTP_API_DAGMAN_PATH by hand.
//
// The zero value means "unknown", and unknown means the package
// defaults: DefaultDagmanPath and a command port. Every discovery
// failure therefore costs the defaults rather than the workflow.
type Layout struct {
	// BinDir is the access point's $(BIN). Empty when it could not be
	// read, or when it is relative -- a relative BIN cannot be joined
	// onto anything meaningful from a process that is not in the access
	// point's filesystem.
	BinDir string
	// DisablePort mirrors the access point's DAGMAN_DISABLE_PORT.
	DisablePort bool
}

// ConfigReader is the one thing layout discovery needs of a schedd:
// DC_CONFIG_VAL, which is a READ-level command and so needs no
// privilege. *htcondor.Schedd satisfies it.
//
// It is an interface rather than the concrete type so this package stays
// testable without a pool, and so the two servers that submit workflows
// (REST and MCP) can share one discovery instead of each writing their
// own and drifting apart.
type ConfigReader interface {
	ConfigVal(ctx context.Context, name string) (string, bool, error)
}

// DiscoverLayout asks a schedd about its DAGMan installation.
//
// It never fails: every kind of "no answer" -- an error, an unset knob,
// an empty value, a nil reader -- yields the zero Layout. debug may be
// nil; when it is not, it is called once with the result, so an operator
// chasing a wrong condor_dagman path can see what the schedd said.
//
// Callers holding a possibly-nil concrete schedd must check it BEFORE
// passing it here: a typed nil wrapped in an interface is not nil, and
// the method call would panic rather than fall back to the defaults.
func DiscoverLayout(ctx context.Context, sc ConfigReader, debug func(msg string, args ...any)) Layout {
	if sc == nil {
		return Layout{}
	}
	var out Layout
	out.BinDir = configVal(ctx, sc, "BIN", debug)
	if out.BinDir != "" && !path.IsAbs(out.BinDir) {
		out.BinDir = ""
	}
	out.DisablePort = isConfigTrue(configVal(ctx, sc, "DAGMAN_DISABLE_PORT", debug))
	if debug != nil {
		debug("DAGMan layout discovered from the schedd", "bin", out.BinDir, "disable_port", out.DisablePort)
	}
	return out
}

// configVal reads one knob, treating every kind of "no answer" the same.
// daemon core reports an unset parameter as the literal string "Not
// defined", which ConfigVal recognizes -- but a daemon that phrases it
// differently would hand back that sentence as a value, so the prefix is
// checked here too. An empty BIN in particular must not become
// "/condor_dagman".
func configVal(ctx context.Context, sc ConfigReader, name string, debug func(msg string, args ...any)) string {
	value, ok, err := sc.ConfigVal(ctx, name)
	if err != nil {
		if debug != nil {
			debug("could not read a config value from the schedd", "knob", name, "error", err)
		}
		return ""
	}
	if !ok {
		return ""
	}
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "Not defined") {
		return ""
	}
	return value
}

// isConfigTrue reads HTCondor's boolean spelling.
func isConfigTrue(v string) bool {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "TRUE", "T", "YES", "Y", "1":
		return true
	}
	return false
}

// LayoutCache memoises one Layout per access point.
//
// Per access point, not per process: in multi-AP mode a workflow goes to
// whichever AP the caller was assigned, and two APs in one set need not
// have condor_dagman in the same place. Once per AP, because this costs
// a round trip to the schedd on a submit path and the answer changes
// only when the access point is reconfigured -- at which point this
// daemon is restarted alongside it.
//
// The zero value is ready to use.
type LayoutCache struct {
	mu      sync.Mutex
	entries map[string]*layoutEntry
}

// layoutEntry is one access point's memoised layout. The sync.Once is
// what makes two concurrent submissions to the same AP cost one
// discovery rather than two.
type layoutEntry struct {
	once sync.Once
	val  Layout
}

// Get returns key's Layout, calling discover at most once per key.
//
// key names the access point; the empty string is the right key in
// single-AP mode, where there is only one.
func (c *LayoutCache) Get(ctx context.Context, key string, discover func(context.Context) Layout) Layout {
	key = strings.ToLower(strings.TrimSpace(key))
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]*layoutEntry{}
	}
	e, ok := c.entries[key]
	if !ok {
		e = &layoutEntry{}
		c.entries[key] = e
	}
	c.mu.Unlock()
	e.once.Do(func() {
		if discover != nil {
			e.val = discover(ctx)
		}
	})
	return e.val
}
