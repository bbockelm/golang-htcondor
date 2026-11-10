package htcondor

import "github.com/bbockelm/golang-htcondor/config"

// The WithConfig methods below give a client object an explicit HTCondor
// configuration. Without one -- the default, and a nil cfg -- the object reads
// the process-wide configuration loaded from $CONDOR_CONFIG (GetDefaultConfig,
// ReloadDefaultConfig) and uses the process-wide rate limiter, as it always has.
//
// With one, every connection the object makes reads its SEC_* settings and
// daemon credential locations (token directories, pool password, SSL client
// certificate) from cfg, and its query rate limits from cfg's
// *_QUERY_RATE_LIMIT knobs; the process-wide configuration is not consulted.
// cfg changes only where the configuration comes from. Which credential is
// presented is decided exactly as before: a SecurityConfig on the request
// context still wins, and the daemon-fallback policy (WithDaemonCredential,
// SetUnmarkedOriginPolicy) still gates the configured identity.
//
// They are fluent modifiers, like Collector.WithRaceStagger, so they compose
// with the constructors:
//
//	schedd := htcondor.NewSchedd(name, addr).WithConfig(cfg)
//
// Set the configuration before the object is shared between goroutines.

// WithConfig sets the HTCondor configuration this Schedd uses; see the note
// above. It also applies to the JobConnectInfo it returns.
func (s *Schedd) WithConfig(cfg *config.Config) *Schedd {
	s.cfg = cfg
	return s
}

// WithConfig sets the HTCondor configuration this Collector uses; see the
// note above.
func (c *Collector) WithConfig(cfg *config.Config) *Collector {
	c.cfg = cfg
	return c
}

// WithConfig sets the HTCondor configuration this credd client uses; see the
// note above.
func (c *CedarCredd) WithConfig(cfg *config.Config) *CedarCredd {
	c.cfg = cfg
	return c
}

// WithConfig sets the HTCondor configuration this placementd client uses; see
// the note above. The client's authentication and encryption requirements are
// not configurable either way.
func (p *Placementd) WithConfig(cfg *config.Config) *Placementd {
	p.cfg = cfg
	return p
}

// WithConfig sets the HTCondor configuration this Startd uses; see the note
// above.
func (s *Startd) WithConfig(cfg *config.Config) *Startd {
	s.cfg = cfg
	return s
}

// WithConfig sets the HTCondor configuration the Master's CEDAR sender uses
// for keepalives and readiness; see the note above.
func (m *Master) WithConfig(cfg *config.Config) *Master {
	m.cfg = cfg
	if cs, ok := m.sender.(*cedarMasterSender); ok {
		cs.cfg = cfg
	}
	return m
}
