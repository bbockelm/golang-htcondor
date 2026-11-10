package apassign

import (
	"fmt"
	"strings"
	"time"
)

// Backend names, as HTTP_API_AP_ASSIGNMENT lists them.
const (
	BackendStatic  = "static"
	BackendMapfile = "mapfile"
	BackendREST    = "rest"
)

// Config is the HTTP_API_AP_ASSIGNMENT* configuration.
type Config struct {
	// Backends is HTTP_API_AP_ASSIGNMENT, in order. Empty means static.
	Backends []string
	// Default is HTTP_API_AP_ASSIGNMENT_DEFAULT.
	Default string
	// Static is the schedd the static backend assigns. In multi-AP mode
	// it is Default.
	Static string
	// Mapfile is HTTP_API_AP_ASSIGNMENT_MAPFILE.
	Mapfile string
	// RESTURL and RESTTokenFile are HTTP_API_AP_ASSIGNMENT_REST_URL and
	// _REST_TOKEN_FILE.
	RESTURL       string
	RESTTokenFile string
	// REST tunes the rest backend (tests).
	REST RESTOptions
	// Stale is HTTP_API_AP_ASSIGNMENT_STALE_SECONDS; zero means
	// DefaultStale.
	Stale time.Duration
}

// ParseBackends reads an HTTP_API_AP_ASSIGNMENT value: names separated by
// commas or spaces, case-insensitive. An unknown name is an error, so a
// typo refuses to start the server instead of dropping a backend.
func ParseBackends(spec string) ([]string, error) {
	var out []string
	for _, f := range strings.FieldsFunc(spec, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		name := strings.ToLower(strings.TrimSpace(f))
		switch name {
		case BackendStatic, BackendMapfile, BackendREST:
			out = append(out, name)
		default:
			return nil, fmt.Errorf("HTTP_API_AP_ASSIGNMENT: unknown backend %q (known: %s, %s, %s)",
				f, BackendStatic, BackendMapfile, BackendREST)
		}
	}
	return out, nil
}

// Build assembles the chain cfg describes. opts supplies validation,
// logging and the clock; its Default and Stale are taken from cfg.
func Build(cfg Config, opts Options) (*Chain, error) {
	names := cfg.Backends
	if len(names) == 0 {
		names = []string{BackendStatic}
	}
	var backends []Backend
	for _, name := range names {
		switch strings.ToLower(name) {
		case BackendStatic:
			backends = append(backends, Backend{Name: BackendStatic, Assigner: &Static{Schedd: cfg.Static}, DefaultTTL: fallbackTTL})
		case BackendMapfile:
			m, err := NewMapfile(cfg.Mapfile, opts.Logger)
			if err != nil {
				return nil, err
			}
			backends = append(backends, Backend{Name: BackendMapfile, Assigner: m, DefaultTTL: DefaultMapfileTTL})
		case BackendREST:
			r, err := NewREST(cfg.RESTURL, cfg.RESTTokenFile, cfg.REST)
			if err != nil {
				return nil, err
			}
			backends = append(backends, Backend{Name: BackendREST, Assigner: r, DefaultTTL: DefaultRESTTTL})
		default:
			return nil, fmt.Errorf("HTTP_API_AP_ASSIGNMENT: unknown backend %q", name)
		}
	}
	opts.Default = cfg.Default
	opts.Stale = cfg.Stale
	return NewChain(backends, opts)
}
