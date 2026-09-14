package dbmirror

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/golang-htcondor/config"
)

func testConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	cfg, err := config.NewFromReader(strings.NewReader(body))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// withStatusQuery swaps the status exchange for the duration of a test.
func withStatusQuery(t *testing.T, fn func(*Locator, context.Context, string) (*classad.ClassAd, error)) {
	t.Helper()
	prev := statusQuery
	statusQuery = fn
	t.Cleanup(func() { statusQuery = prev })
}

func statusAd(name, advertised string) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttrString("MyType", AdType)
	ad.InsertAttrString("Name", name)
	ad.InsertAttrString("MyAddress", advertised)
	ad.InsertAttrBool("Ok", true)
	return ad
}

// TestEnabledWithConfiguredAddress: an operator who names the database has said
// where it is. Requiring a collector on top of that made the knob useless alone.
func TestEnabledWithConfiguredAddress(t *testing.T) {
	cfg := testConfig(t, "")
	if l := NewLocatorWithOptions(nil, cfg, Options{Address: "<10.0.0.1:9618>"}); !l.Enabled() {
		t.Error("a configured address alone does not enable routing")
	}
	if l := NewLocatorWithOptions(nil, cfg, Options{}); l.Enabled() {
		t.Error("routing is enabled with neither a collector nor an address")
	}
}

// TestLocalAddressFromAddressFile is the path every other htcondordb client on
// the host already uses, and the one this package was missing.
func TestLocalAddressFromAddressFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".htcondordb_address")
	if err := os.WriteFile(path, []byte("<127.0.0.1:12345?sock=db>\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Via LOG, which is how it resolves on a stock deployment.
	l := NewLocatorWithOptions(nil, testConfig(t, "LOG = "+dir+"\n"), Options{})
	addr, source, err := l.localAddress()
	if err != nil {
		t.Fatalf("resolving from $(LOG): %v", err)
	}
	if addr != "<127.0.0.1:12345?sock=db>" {
		t.Errorf("addr = %q", addr)
	}
	if source == "" {
		t.Error("no source described for the operator")
	}

	// An explicit address wins over the file.
	l = NewLocatorWithOptions(nil, testConfig(t, "LOG = "+dir+"\n"), Options{Address: "<10.0.0.9:9618>"})
	if addr, _, err = l.localAddress(); err != nil || addr != "<10.0.0.9:9618>" {
		t.Errorf("configured address did not win: addr=%q err=%v", addr, err)
	}
}

// TestLocalAddressMissingFile reports the path rather than a bare ENOENT, since
// the whole question an operator has is which path was consulted.
func TestLocalAddressMissingFile(t *testing.T) {
	l := NewLocatorWithOptions(nil, testConfig(t, "LOG = "+t.TempDir()+"\n"), Options{})
	_, _, err := l.localAddress()
	if err == nil {
		t.Fatal("resolved an address file that does not exist")
	}
	if !strings.Contains(err.Error(), ".htcondordb_address") {
		t.Errorf("error does not name the path consulted: %v", err)
	}
}

// TestDiscoverLocalDialsTheResolvedAddress: the ad advertises the address the
// collector should use, which is not necessarily reachable from here -- that it
// was not is a reason to be on this path at all.
func TestDiscoverLocalDialsTheResolvedAddress(t *testing.T) {
	withStatusQuery(t, func(_ *Locator, _ context.Context, _ string) (*classad.ClassAd, error) {
		return statusAd("db@example.org", "<192.0.2.1:9618>"), nil
	})
	l := NewLocatorWithOptions(nil, testConfig(t, ""), Options{Address: "<127.0.0.1:12345>"})

	info, err := l.discoverLocal(context.Background())
	if err != nil {
		t.Fatalf("discoverLocal: %v", err)
	}
	if info.Address != "<127.0.0.1:12345>" {
		t.Errorf("Address = %q, want the address we resolved and dialled", info.Address)
	}
	if info.Name != "db@example.org" {
		t.Errorf("Name = %q", info.Name)
	}
}

// TestDiscoverLocalRejectsNameMismatch: an operator who named a database meant
// that one. A different database running on this host is not a substitute.
func TestDiscoverLocalRejectsNameMismatch(t *testing.T) {
	withStatusQuery(t, func(*Locator, context.Context, string) (*classad.ClassAd, error) {
		return statusAd("other@example.org", ""), nil
	})
	l := NewLocatorWithOptions(nil, testConfig(t, ""), Options{
		Address: "<127.0.0.1:12345>",
		Name:    "wanted@example.org",
	})

	if _, err := l.discoverLocal(context.Background()); err == nil {
		t.Fatal("routed to a database with the wrong name")
	}
}

// TestDiscoverLocalRejectsForeignAd guards the consequence of ParseAd being
// best-effort: anything that is not an htcondordb ad parses into a zero Info,
// which reads as a database that has never synced rather than as an error.
func TestDiscoverLocalRejectsForeignAd(t *testing.T) {
	withStatusQuery(t, func(*Locator, context.Context, string) (*classad.ClassAd, error) {
		ad := classad.New()
		ad.InsertAttrString("MyType", "Machine")
		return ad, nil
	})
	l := NewLocatorWithOptions(nil, testConfig(t, ""), Options{Address: "<127.0.0.1:12345>"})

	_, err := l.discoverLocal(context.Background())
	if err == nil {
		t.Fatal("accepted an ad that is not an htcondordb ad")
	}
	if !strings.Contains(err.Error(), AdType) {
		t.Errorf("error does not say what kind of ad was expected: %v", err)
	}
}

// TestDiscoverFallsBackWhenNothingAdvertises is the reported case: the database
// is running and reachable, but its advertisement is not reaching the collector.
func TestDiscoverFallsBackWhenNothingAdvertises(t *testing.T) {
	withStatusQuery(t, func(*Locator, context.Context, string) (*classad.ClassAd, error) {
		return statusAd("db@example.org", ""), nil
	})
	// No collector, an address the operator pinned: discover must not stop at
	// the collector step.
	l := NewLocatorWithOptions(nil, testConfig(t, ""), Options{Address: "<127.0.0.1:12345>"})

	info, err := l.discover(context.Background())
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if info.Name != "db@example.org" {
		t.Errorf("Name = %q", info.Name)
	}
}

// TestDiscoverReportsBothFailures: when the collector knows nothing and the
// local daemon cannot be reached either, an operator needs both halves.
func TestDiscoverReportsBothFailures(t *testing.T) {
	withStatusQuery(t, func(*Locator, context.Context, string) (*classad.ClassAd, error) {
		return nil, errors.New("connection refused")
	})
	l := NewLocatorWithOptions(nil, testConfig(t, ""), Options{Address: "<127.0.0.1:12345>"})

	_, err := l.discover(context.Background())
	if err == nil {
		t.Fatal("discover succeeded with nothing to discover")
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("the local failure is missing: %v", err)
	}
}
