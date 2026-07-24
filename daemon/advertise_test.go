package daemon

import (
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/config"
)

func testDaemon(t *testing.T, cfg *config.Config) *Daemon {
	t.Helper()
	d := &Daemon{subsys: "HTCONDORDB", startTime: time.Now()}
	d.cfg.Store(cfg)
	return d
}

func TestBuildAdvertisement(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("FULL_HOSTNAME", "ap40.chtc.wisc.edu")
	d := testDaemon(t, cfg)

	ac := AdvertiseConfig{
		MyType: "HTCondorDB",
		Augment: func(ad *classad.ClassAd) {
			ad.InsertAttr("TotalAds", 42)
			ad.InsertAttrString("Custom", "hello")
		},
	}
	ad := d.buildAdvertisement(ac, 5)

	if v, _ := ad.EvaluateAttrString("MyType"); v != "HTCondorDB" {
		t.Errorf("MyType = %q", v)
	}
	if v, _ := ad.EvaluateAttrInt("UpdateSequenceNumber"); v != 5 {
		t.Errorf("UpdateSequenceNumber = %d, want 5", v)
	}
	// PublishAd base attribute present (identity from the daemon).
	if v, _ := ad.EvaluateAttrString("Machine"); v != "ap40.chtc.wisc.edu" {
		t.Errorf("Machine = %q (PublishAd base not applied)", v)
	}
	// Subsystem augmentation present.
	if v, _ := ad.EvaluateAttrInt("TotalAds"); v != 42 {
		t.Errorf("TotalAds = %d, want 42 (augment)", v)
	}
	if v, _ := ad.EvaluateAttrString("Custom"); v != "hello" {
		t.Errorf("Custom = %q (augment)", v)
	}
}

func TestDaemonShutdownTriggered(t *testing.T) {
	newAd := func() *classad.ClassAd {
		ad := classad.New()
		ad.InsertAttr("TotalAds", 0)
		ad.InsertAttrBool("Draining", true)
		return ad
	}

	t.Run("unset never triggers", func(t *testing.T) {
		d := testDaemon(t, config.NewEmpty())
		if knob, fire := d.daemonShutdownTriggered(newAd()); fire {
			t.Errorf("unexpected shutdown: knob=%q", knob)
		}
	})

	t.Run("graceful expression true", func(t *testing.T) {
		cfg := config.NewEmpty()
		cfg.Set("DAEMON_SHUTDOWN", "TotalAds == 0")
		d := testDaemon(t, cfg)
		knob, fire := d.daemonShutdownTriggered(newAd())
		if !fire || knob != "DAEMON_SHUTDOWN" {
			t.Errorf("expected DAEMON_SHUTDOWN, got knob=%q fire=%v", knob, fire)
		}
	})

	t.Run("fast takes precedence", func(t *testing.T) {
		cfg := config.NewEmpty()
		cfg.Set("DAEMON_SHUTDOWN", "TotalAds == 0")
		cfg.Set("DAEMON_SHUTDOWN_FAST", "Draining")
		d := testDaemon(t, cfg)
		knob, fire := d.daemonShutdownTriggered(newAd())
		if !fire || knob != "DAEMON_SHUTDOWN_FAST" {
			t.Errorf("expected DAEMON_SHUTDOWN_FAST, got knob=%q fire=%v", knob, fire)
		}
	})

	t.Run("false expression does not trigger", func(t *testing.T) {
		cfg := config.NewEmpty()
		cfg.Set("DAEMON_SHUTDOWN", "TotalAds > 100")
		d := testDaemon(t, cfg)
		if _, fire := d.daemonShutdownTriggered(newAd()); fire {
			t.Error("false expression should not trigger shutdown")
		}
	})

	t.Run("non-boolean expression does not trigger", func(t *testing.T) {
		cfg := config.NewEmpty()
		cfg.Set("DAEMON_SHUTDOWN", "TotalAds + 1")
		d := testDaemon(t, cfg)
		if _, fire := d.daemonShutdownTriggered(newAd()); fire {
			t.Error("non-boolean expression should not trigger shutdown")
		}
	})
}

func TestUpdateInterval(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		d := testDaemon(t, config.NewEmpty())
		if got := d.updateInterval(); got != DefaultUpdateInterval {
			t.Errorf("interval = %v, want default %v", got, DefaultUpdateInterval)
		}
	})
	t.Run("UPDATE_INTERVAL", func(t *testing.T) {
		cfg := config.NewEmpty()
		cfg.Set("UPDATE_INTERVAL", "60")
		d := testDaemon(t, cfg)
		if got := d.updateInterval(); got != 60*time.Second {
			t.Errorf("interval = %v, want 60s", got)
		}
	})
	t.Run("subsys-specific wins", func(t *testing.T) {
		cfg := config.NewEmpty()
		cfg.Set("UPDATE_INTERVAL", "60")
		cfg.Set("HTCONDORDB_UPDATE_INTERVAL", "30")
		d := testDaemon(t, cfg)
		if got := d.updateInterval(); got != 30*time.Second {
			t.Errorf("interval = %v, want 30s (subsys-specific)", got)
		}
	})
}
