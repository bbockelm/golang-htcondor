package daemon

import (
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/config"
)

func TestPublishAd(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("FULL_HOSTNAME", "ap40.chtc.wisc.edu")
	cfg.Set("PRIVATE_NETWORK_NAME", "chtc")
	// Admin-published attributes, the config_fill_ad mechanism.
	cfg.Set("HTCONDORDB_ATTRS", "PoolName, MaxJobs")
	cfg.Set("PoolName", `"CHTC"`)
	cfg.Set("MaxJobs", "100000")

	d := &Daemon{subsys: "HTCONDORDB", startTime: time.Now().Add(-90 * time.Second)}
	d.cfg.Store(cfg)

	ad := classad.New()
	d.PublishAd(ad)

	str := func(k string) string { v, _ := ad.EvaluateAttrString(k); return v }
	i := func(k string) int64 { v, _ := ad.EvaluateAttrInt(k); return v }

	if str("Machine") != "ap40.chtc.wisc.edu" {
		t.Errorf("Machine = %q", str("Machine"))
	}
	if str("Name") != "htcondordb@ap40.chtc.wisc.edu" {
		t.Errorf("Name = %q, want htcondordb@ap40.chtc.wisc.edu", str("Name"))
	}
	if str("PrivateNetworkName") != "chtc" {
		t.Errorf("PrivateNetworkName = %q", str("PrivateNetworkName"))
	}
	if v := str("CondorVersion"); !strings.HasPrefix(v, "$CondorVersion:") || !strings.Contains(v, "golang-htcondor") {
		t.Errorf("CondorVersion = %q", v)
	}
	if v := str("CondorPlatform"); !strings.HasPrefix(v, "$CondorPlatform:") {
		t.Errorf("CondorPlatform = %q", v)
	}
	if i("DaemonStartTime") <= 0 || i("MyCurrentTime") <= 0 {
		t.Errorf("timing attrs missing")
	}
	if age := i("MonitorSelfAge"); age < 80 || age > 3600 {
		t.Errorf("MonitorSelfAge = %d, want ~90", age)
	}
	if i("MonitorSelfImageSize") <= 0 {
		t.Errorf("MonitorSelfImageSize should be > 0")
	}

	// config_fill_ad: the two admin-published attributes appear with their configured values.
	if str("PoolName") != "CHTC" {
		t.Errorf("PoolName = %q, want CHTC (from HTCONDORDB_ATTRS)", str("PoolName"))
	}
	if i("MaxJobs") != 100000 {
		t.Errorf("MaxJobs = %d, want 100000 (from HTCONDORDB_ATTRS)", i("MaxJobs"))
	}
}

// TestPublishAdNameOverride: <SUBSYS>_NAME overrides the default subsys@host name.
func TestPublishAdNameOverride(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("FULL_HOSTNAME", "h1")
	cfg.Set("HTCONDORDB_NAME", "primary-db")
	d := &Daemon{subsys: "HTCONDORDB", startTime: time.Now()}
	d.cfg.Store(cfg)
	ad := classad.New()
	d.PublishAd(ad)
	if v, _ := ad.EvaluateAttrString("Name"); v != "primary-db" {
		t.Errorf("Name = %q, want primary-db", v)
	}
}
