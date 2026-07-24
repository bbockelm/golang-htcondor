package daemon

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// DefaultUpdateInterval is the collector-advertisement cadence when no config knob sets it.
const DefaultUpdateInterval = 5 * time.Minute

// AdvertiseConfig configures a daemon's periodic collector advertisement. The daemon builds a
// base ad (PublishAd) and the subsystem supplies its own attributes via Augment.
type AdvertiseConfig struct {
	// MyType is the advertised ad's MyType (e.g. "HTCondorDB"). Required.
	MyType string
	// Command is the UPDATE_* command; the zero value derives it from MyType (a non-standard
	// MyType routes via UPDATE_AD_GENERIC).
	Command commands.CommandType
	// Interval overrides the update cadence. Zero uses <SUBSYS>_UPDATE_INTERVAL, then
	// UPDATE_INTERVAL, then DefaultUpdateInterval.
	Interval time.Duration
	// Augment adds the subsystem's attributes to the ad after PublishAd has seeded the common
	// ones. Optional.
	Augment func(*classad.ClassAd)
	// Logger defaults to the daemon's slog logger.
	Logger *slog.Logger
}

// Advertise runs the collector-advertisement loop until ctx is cancelled -- the Go analogue of
// a DaemonCore daemon's periodic UpdateCollector timer + sendUpdates. Each cycle it builds the
// ad (PublishAd + MyType + a monotonic UpdateSequenceNumber + Augment), evaluates the
// DAEMON_SHUTDOWN / DAEMON_SHUTDOWN_FAST expressions against it (requesting daemon shutdown when
// one is true, as C++ sendUpdates does), and sends it to every collector in COLLECTOR_HOST. On
// exit it INVALIDATEs the ad so the collector expires it promptly. It is a no-op (logs once)
// when no collector is configured.
func (d *Daemon) Advertise(ctx context.Context, cfg AdvertiseConfig) {
	log := cfg.Logger
	if log == nil {
		log = d.Slog()
	}
	conf := d.cfg.Load()
	hosts := splitConfigList(configGet(conf, "COLLECTOR_HOST"))
	if len(hosts) == 0 {
		log.Info("no COLLECTOR_HOST configured; not advertising", "ad_type", cfg.MyType)
		return
	}
	collectors := make([]*htcondor.Collector, len(hosts))
	for i, h := range hosts {
		collectors[i] = htcondor.NewCollector(h)
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = d.updateInterval()
	}
	log.Info("advertising to collector", "ad_type", cfg.MyType, "collectors", len(hosts), "interval", interval.String())

	var seq int64
	send := func() {
		seq++
		ad := d.buildAdvertisement(cfg, seq)
		// Evaluate DAEMON_SHUTDOWN against the ad and request shutdown if it fires; the update is
		// still sent this cycle (mirroring C++), and the cancelled ctx then unwinds the loop.
		if knob, fire := d.daemonShutdownTriggered(ad); fire {
			log.Info("daemon shutdown expression is true; requesting shutdown", "knob", knob)
			d.Shutdown()
		}
		for i, c := range collectors {
			if err := c.Advertise(ctx, ad, &htcondor.AdvertiseOptions{Command: cfg.Command}); err != nil {
				log.Warn("collector advertise failed", "collector", hosts[i], "err", err.Error())
			}
		}
	}

	send() // advertise immediately, don't wait a full interval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.invalidate(collectors, hosts, cfg, log)
			return
		case <-ticker.C:
			send()
		}
	}
}

// buildAdvertisement assembles one advertisement: the common base ad (PublishAd), the
// subsystem's MyType and sequence number, and the subsystem-specific attributes (Augment).
func (d *Daemon) buildAdvertisement(cfg AdvertiseConfig, seq int64) *classad.ClassAd {
	ad := classad.New()
	d.PublishAd(ad)
	ad.InsertAttrString("MyType", cfg.MyType)
	ad.InsertAttr("UpdateSequenceNumber", seq)
	if cfg.Augment != nil {
		cfg.Augment(ad)
	}
	return ad
}

// daemonShutdownTriggered evaluates DAEMON_SHUTDOWN_FAST then DAEMON_SHUTDOWN against the ad and
// returns the knob whose expression is true (fast checked first). An unset or non-boolean
// expression never triggers.
func (d *Daemon) daemonShutdownTriggered(ad *classad.ClassAd) (string, bool) {
	conf := d.cfg.Load()
	for _, knob := range []string{"DAEMON_SHUTDOWN_FAST", "DAEMON_SHUTDOWN"} {
		exprStr := configGet(conf, knob)
		if exprStr == "" {
			continue
		}
		expr, err := classad.ParseExpr(exprStr)
		if err != nil {
			continue
		}
		v := expr.Eval(ad)
		if !v.IsBool() {
			continue
		}
		if b, berr := v.BoolValue(); berr == nil && b {
			return knob, true
		}
	}
	return "", false
}

// updateInterval resolves the advertisement cadence: <SUBSYS>_UPDATE_INTERVAL, then
// UPDATE_INTERVAL, then DefaultUpdateInterval.
func (d *Daemon) updateInterval() time.Duration {
	conf := d.cfg.Load()
	for _, knob := range []string{d.subsys + "_UPDATE_INTERVAL", "UPDATE_INTERVAL"} {
		if s := configGet(conf, knob); s != "" {
			if n, err := strconv.Atoi(s); err == nil && n > 0 {
				return time.Duration(n) * time.Second
			}
		}
	}
	return DefaultUpdateInterval
}

// invalidate asks each collector to expire our ad on shutdown (best effort, on a fresh short
// context since ctx is already cancelled).
func (d *Daemon) invalidate(collectors []*htcondor.Collector, hosts []string, cfg AdvertiseConfig, log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	q := classad.New()
	q.InsertAttrString("MyType", "Query")
	q.InsertAttrString("TargetType", cfg.MyType)
	q.InsertAttrString("Name", d.adName(d.cfg.Load()))
	for i, c := range collectors {
		if err := c.Advertise(ctx, q, &htcondor.AdvertiseOptions{Command: commands.INVALIDATE_ADS_GENERIC}); err != nil {
			log.Warn("collector invalidate failed", "collector", hosts[i], "err", err.Error())
		}
	}
}
