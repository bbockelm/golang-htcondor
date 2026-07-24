package daemon

import (
	"math"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/version"
)

// PublishAd fills ad with the common daemon attributes every collector advertisement carries --
// the Go analogue of C++ DaemonCore::publish() + config_fill_ad(). A daemon seeds a base ad with
// this, then adds its own subsystem attributes (and sets MyType) before sending it to a
// collector. PublishAd does NOT set MyType, which is subsystem-specific.
//
// It publishes identity (Name, Machine FQDN, MyAddress), CondorVersion/CondorPlatform,
// MyCurrentTime, DaemonStartTime/DaemonLastReconfigTime, PrivateNetworkName, a subset of the
// self-monitoring MonitorSelf* stats, and any admin-configured <SUBSYS>_ATTRS attributes (so an
// operator can augment every advertisement via configuration, exactly as with a C++ daemon).
func (d *Daemon) PublishAd(ad *classad.ClassAd) {
	cfg := d.cfg.Load()
	now := time.Now()

	ad.InsertAttr("MyCurrentTime", now.Unix())
	ad.InsertAttrString("CondorVersion", CondorVersion())
	ad.InsertAttrString("CondorPlatform", CondorPlatform())
	ad.InsertAttr("DaemonStartTime", d.startTime.Unix())
	if r := d.lastReconfig.Load(); r > 0 {
		ad.InsertAttr("DaemonLastReconfigTime", r)
	}
	if m := configGet(cfg, "FULL_HOSTNAME"); m != "" {
		ad.InsertAttrString("Machine", m)
	}
	if addr, ok := d.AdvertisedSinful(); ok && addr != "" {
		ad.InsertAttrString("MyAddress", ensureAngle(addr))
	}
	if pnn := configGet(cfg, "PRIVATE_NETWORK_NAME"); pnn != "" {
		ad.InsertAttrString("PrivateNetworkName", pnn)
	}
	ad.InsertAttrString("Name", d.adName(cfg))

	d.publishMonitorSelf(ad, now)
	d.fillConfigAttrs(ad, cfg)
}

// CondorVersion / CondorPlatform format the library's version/platform in the HTCondor
// "$CondorVersion: ... $" / "$CondorPlatform: ... $" shapes (BuildID marks golang-htcondor), the
// values a C++ daemon publishes via CondorVersion()/CondorPlatform().
func CondorVersion() string {
	return "$CondorVersion: " + version.Version + " BuildID: golang-htcondor-" + version.Commit + " $"
}

// CondorPlatform returns the "$CondorPlatform: <arch>_<os> $" string a C++ daemon publishes.
func CondorPlatform() string {
	return "$CondorPlatform: " + runtime.GOARCH + "_" + runtime.GOOS + " $"
}

// adName returns the daemon's advertised Name: <SUBSYS>_NAME if configured, else
// <subsys>@<full-hostname>.
func (d *Daemon) adName(cfg *config.Config) string {
	if n := configGet(cfg, d.subsys+"_NAME"); n != "" {
		return n
	}
	host := configGet(cfg, "FULL_HOSTNAME")
	if host == "" {
		host, _ = os.Hostname()
	}
	return strings.ToLower(d.subsys) + "@" + host
}

// publishMonitorSelf adds the self-monitoring gauges a Prometheus exporter (or condor_status)
// reads. Age comes from the daemon's start time; the memory figures are the Go runtime's view
// (Sys ~ address space obtained from the OS, HeapAlloc ~ live heap) rather than the OS process
// RSS, and are reported in KiB to match the HTCondor MonitorSelf* convention.
func (d *Daemon) publishMonitorSelf(ad *classad.ClassAd, now time.Time) {
	ad.InsertAttr("MonitorSelfTime", now.Unix())
	ad.InsertAttr("MonitorSelfAge", int64(now.Sub(d.startTime).Seconds()))
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	ad.InsertAttr("MonitorSelfImageSize", kib(ms.Sys))
	ad.InsertAttr("MonitorSelfResidentSetSize", kib(ms.HeapAlloc))
}

// kib converts a byte count to a KiB int64, saturating rather than overflowing (a process
// never approaches the bound, but the explicit clamp keeps the uint64->int64 conversion safe).
func kib(bytes uint64) int64 {
	kb := bytes / 1024
	if kb > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(kb)
}

// fillConfigAttrs mirrors config_fill_ad: it publishes each attribute named in <SUBSYS>_ATTRS
// (and <SUBSYS>_EXPRS, SYSTEM_<SUBSYS>_ATTRS, and the local-name-prefixed forms) by inserting
// that attribute's configured value -- parsed as a ClassAd expression, falling back to a string.
func (d *Daemon) fillConfigAttrs(ad *classad.ClassAd, cfg *config.Config) {
	subsys := d.subsys
	local := cfg.Options().LocalName

	var names []string
	seen := map[string]bool{}
	addList := func(key string) {
		for _, a := range splitConfigList(configGet(cfg, key)) {
			if !seen[a] {
				seen[a] = true
				names = append(names, a)
			}
		}
	}
	addList(subsys + "_ATTRS")
	addList(subsys + "_EXPRS")
	addList("SYSTEM_" + subsys + "_ATTRS")
	if local != "" {
		addList(local + "_" + subsys + "_ATTRS")
		addList(local + "_" + subsys + "_EXPRS")
	}

	for _, name := range names {
		val := configGet(cfg, name)
		if val == "" {
			continue
		}
		if expr, err := classad.ParseExpr(val); err == nil {
			ad.InsertExpr(name, expr)
		} else {
			ad.InsertAttrString(name, val)
		}
	}
}

func configGet(cfg *config.Config, key string) string {
	v, _ := cfg.Get(key)
	return strings.TrimSpace(v)
}

func splitConfigList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
}

func ensureAngle(addr string) string {
	if strings.HasPrefix(addr, "<") {
		return addr
	}
	return "<" + addr + ">"
}
