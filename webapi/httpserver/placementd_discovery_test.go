package httpserver

import (
	"context"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/config"
)

// The access points sharing one collector in these tests: this one, and
// another that runs a placementd.
const (
	thisAPHost        = "ap2001.chtc.wisc.edu"
	otherAPHost       = "townsend-ap4000.chtc.wisc.edu"
	otherPlacementd   = "<128.105.76.18:9618?alias=townsend-ap4000.chtc.wisc.edu&sock=placementd_7607_5906>"
	localPlacementd   = "<128.105.68.20:9618?alias=ap2001.chtc.wisc.edu&sock=placementd_1_2>"
	addressFileSinful = "<128.105.68.20:9618?alias=ap2001.chtc.wisc.edu&sock=placementd_3_4>"
)

// fakeCollector answers ad queries from a fixed set of ads, applying the
// constraint the way a collector would.
type fakeCollector struct {
	t   *testing.T
	ads map[string][]map[string]any
}

func (f *fakeCollector) query(_ context.Context, adType, constraint string, _ []string) ([]*classad.ClassAd, error) {
	var out []*classad.ClassAd
	for _, attrs := range f.ads[adType] {
		if constraint != "" {
			expr, err := classad.ParseExpr(constraint)
			if err != nil {
				f.t.Fatalf("constraint %q: %v", constraint, err)
			}
			probe := f.build(attrs)
			probe.InsertExpr("FakeCollectorMatch", expr)
			if ok, _ := probe.EvaluateAttrBool("FakeCollectorMatch"); !ok {
				continue
			}
		}
		out = append(out, f.build(attrs))
	}
	return out, nil
}

func (f *fakeCollector) build(attrs map[string]any) *classad.ClassAd {
	ad := classad.New()
	for k, v := range attrs {
		if err := ad.Set(k, v); err != nil {
			f.t.Fatalf("set %s: %v", k, err)
		}
	}
	return ad
}

func placementdAd(name, machine, addr string) map[string]any {
	return map[string]any{"MyType": "PlacementD", "Name": name, "Machine": machine, "MyAddress": addr}
}

// sharedCollector is a collector two access points report to. The other
// access point's placementd is listed first, as it was in production.
func sharedCollector(t *testing.T, placementds ...map[string]any) *fakeCollector {
	return &fakeCollector{t: t, ads: map[string][]map[string]any{
		"ScheddAd": {
			{"Name": otherAPHost, "Machine": otherAPHost, "MyAddress": "<128.105.76.18:9618?sock=schedd_1_1>"},
			{"Name": thisAPHost, "Machine": thisAPHost, "MyAddress": "<128.105.68.20:9618?sock=schedd_1_1>"},
		},
		htcondor.PlacementdAdType: placementds,
	}}
}

// discoveryConfig is this host's HTCondor configuration, with a LOG
// directory holding no placementd address file unless a test writes one.
func discoveryConfig(t *testing.T, fullHostname string) (*config.Config, string) {
	t.Helper()
	cfg := config.NewEmpty()
	logDir := t.TempDir()
	cfg.Set("LOG", logDir)
	cfg.Set("FULL_HOSTNAME", fullHostname)
	return cfg, logDir
}

func newTestLocator(t *testing.T, cfg *config.Config, coll *fakeCollector, scheddName string) *placementdLocator {
	return &placementdLocator{
		htcConfig:  cfg,
		scheddName: scheddName,
		query:      coll.query,
		logger:     discoveryLogger(t),
	}
}

// The production failure: the only placementd in the shared collector is
// another access point's. It must not be chosen, and the reason must say
// why, for the one info line an operator reads.
func TestPlacementdDiscoveryIgnoresAnotherAccessPoints(t *testing.T) {
	cfg, _ := discoveryConfig(t, thisAPHost)
	coll := sharedCollector(t, placementdAd(otherAPHost, otherAPHost, otherPlacementd))
	l := newTestLocator(t, cfg, coll, thisAPHost)

	addr, err := l.discover(context.Background())
	if addr != "" {
		t.Fatalf("discovered %q, another access point's placementd", addr)
	}
	if err == nil || !strings.Contains(err.Error(), "none on this access point") {
		t.Errorf("err = %v, want it to say none is on this access point", err)
	}
	if l.lastError() == nil {
		t.Error("lastError is nil after a failed discovery")
	}
}

// With both advertised, this access point's is chosen wherever it falls in
// the collector's answer, and host names compare as DNS does.
func TestPlacementdDiscoveryPrefersThisAccessPoints(t *testing.T) {
	cfg, _ := discoveryConfig(t, thisAPHost)
	coll := sharedCollector(t,
		placementdAd(otherAPHost, otherAPHost, otherPlacementd),
		placementdAd(thisAPHost, "AP2001.CHTC.wisc.edu.", localPlacementd),
	)
	addr, err := newTestLocator(t, cfg, coll, thisAPHost).discover(context.Background())
	if err != nil || addr != localPlacementd {
		t.Fatalf("discover = %q, %v; want %q", addr, err, localPlacementd)
	}
}

// A server in a container in front of the schedd has its own hostname;
// the access point's host comes from the schedd's ad.
func TestPlacementdDiscoveryUsesTheScheddsHost(t *testing.T) {
	cfg, _ := discoveryConfig(t, "htcondor-api-7d9f.pod.cluster.local")
	coll := sharedCollector(t,
		placementdAd(otherAPHost, otherAPHost, otherPlacementd),
		placementdAd(thisAPHost, thisAPHost, localPlacementd),
	)
	addr, err := newTestLocator(t, cfg, coll, thisAPHost).discover(context.Background())
	if err != nil || addr != localPlacementd {
		t.Fatalf("discover = %q, %v; want %q", addr, err, localPlacementd)
	}

	// Named only by address, the schedd is still found.
	l := newTestLocator(t, cfg, coll, "")
	l.scheddAddr = func() string { return "<128.105.68.20:9618?sock=schedd_1_1>" }
	if addr, err := l.discover(context.Background()); err != nil || addr != localPlacementd {
		t.Fatalf("by schedd address: discover = %q, %v; want %q", addr, err, localPlacementd)
	}
}

// An operator can name a placementd on another host, by its ad's Name or by
// address. Nothing else selects one.
func TestPlacementdDiscoveryHonorsTheConfiguredName(t *testing.T) {
	cfg, logDir := discoveryConfig(t, thisAPHost)
	// Even a local address file does not override the operator's choice.
	writeAddressFile(t, logDir, ".placementd_address", addressFileSinful)
	coll := sharedCollector(t,
		placementdAd(thisAPHost, thisAPHost, localPlacementd),
		placementdAd(otherAPHost, otherAPHost, otherPlacementd),
	)

	l := newTestLocator(t, cfg, coll, thisAPHost)
	l.name = strings.ToUpper(otherAPHost)
	if addr, err := l.discover(context.Background()); err != nil || addr != otherPlacementd {
		t.Fatalf("by name: discover = %q, %v; want %q", addr, err, otherPlacementd)
	}

	l.name = "<10.0.0.9:9618?sock=placementd>"
	if addr, err := l.discover(context.Background()); err != nil || addr != l.name {
		t.Fatalf("by address: discover = %q, %v; want %q", addr, err, l.name)
	}

	l.name = "nobody.example.org"
	if addr, err := l.discover(context.Background()); err == nil || addr != "" {
		t.Fatalf("an unadvertised name: discover = %q, %v; want nothing", addr, err)
	}
}

// This host's address file is its own placementd, and wins over the
// collector, whose ad may be a restart behind.
func TestPlacementdDiscoveryPrefersTheAddressFile(t *testing.T) {
	cfg, logDir := discoveryConfig(t, thisAPHost)
	writeAddressFile(t, logDir, ".placementd_address", addressFileSinful)
	coll := sharedCollector(t,
		placementdAd(otherAPHost, otherAPHost, otherPlacementd),
		placementdAd(thisAPHost, thisAPHost, localPlacementd),
	)
	addr, err := newTestLocator(t, cfg, coll, thisAPHost).discover(context.Background())
	if err != nil || addr != addressFileSinful {
		t.Fatalf("discover = %q, %v; want the address file's %q", addr, err, addressFileSinful)
	}
}

// The client's re-resolve runs the same rule: a failed connection, or a
// look for a placementd that appeared later, never lands on another access
// point's.
func TestPlacementdReResolveNeverPicksAnotherAccessPoints(t *testing.T) {
	cfg, _ := discoveryConfig(t, thisAPHost)
	coll := sharedCollector(t, placementdAd(otherAPHost, otherAPHost, otherPlacementd))
	ctx := htcondor.WithDaemonCredential(context.Background(), "test")

	late := htcondor.NewPlacementd("").WithResolver(newTestLocator(t, cfg, coll, thisAPHost).discover)
	if got := late.Resolve(ctx); got != "" {
		t.Errorf("Resolve found %q, another access point's placementd", got)
	}

	const stale = "<127.0.0.1:1>"
	moved := htcondor.NewPlacementd(stale).WithResolver(newTestLocator(t, cfg, coll, thisAPHost).discover)
	if _, err := moved.QueryUsers(ctx, ""); err == nil {
		t.Fatal("QueryUsers against a closed port succeeded")
	}
	if got := moved.Address(); got != stale {
		t.Errorf("after a failed connection the client moved to %q", got)
	}
}
