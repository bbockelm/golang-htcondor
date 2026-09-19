package main

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/webapi/mcpserver"
)

// Every knob must survive the trip from configuration into the struct the
// MCP server reads. This is the layer where a setting goes missing: it is
// nine values copied by hand, and a dropped one is silent -- the operator
// sets a cap, nothing enforces it, and nothing says so.
func TestLoadBuildConfigCarriesEverySetting(t *testing.T) {
	cfg := config.NewEmpty()
	for k, v := range map[string]string{
		"HTTP_API_BUILD_EXTRA_SUBMIT":      "+IsBuildJob = True\nkeep_claim_idle = 1200",
		"HTTP_API_BUILD_REQUIREMENTS":      "TARGET.IsBuildSlot",
		"HTTP_API_BUILD_STAGING_BASE":      "osdf:///chtc/staging/b/alice",
		"HTTP_API_BUILD_DEFAULT_CPUS":      "8",
		"HTTP_API_BUILD_DEFAULT_MEMORY_MB": "16384",
		"HTTP_API_BUILD_DEFAULT_DISK_MB":   "30720",
		"HTTP_API_BUILD_MAX_CPUS":          "32",
		"HTTP_API_BUILD_MAX_MEMORY_MB":     "65536",
		"HTTP_API_BUILD_MAX_DISK_MB":       "102400",
	} {
		cfg.Set(k, v)
	}

	got := loadBuildConfig(cfg, ccbTestLogger(t))

	if got.ExtraSubmit != "+IsBuildJob = True\nkeep_claim_idle = 1200" {
		t.Errorf("ExtraSubmit = %q", got.ExtraSubmit)
	}
	if got.Requirements != "TARGET.IsBuildSlot" {
		t.Errorf("Requirements = %q", got.Requirements)
	}
	if got.StagingBase != "osdf:///chtc/staging/b/alice" {
		t.Errorf("StagingBase = %q", got.StagingBase)
	}
	for _, c := range []struct {
		name string
		got  int
		want int
	}{
		{"DefaultCpus", got.DefaultCpus, 8},
		{"DefaultMemoryMB", got.DefaultMemoryMB, 16384},
		{"DefaultDiskMB", got.DefaultDiskMB, 30720},
		{"MaxCpus", got.MaxCpus, 32},
		{"MaxMemoryMB", got.MaxMemoryMB, 65536},
		{"MaxDiskMB", got.MaxDiskMB, 102400},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// An unconfigured server still has to work: build_container falls back to
// its built-in resource defaults and requires the caller to name a
// destination.
func TestLoadBuildConfigEmptyIsZero(t *testing.T) {
	got := loadBuildConfig(config.NewEmpty(), ccbTestLogger(t))
	var want mcpserver.BuildConfig
	if got != want {
		t.Errorf("an empty configuration should produce a zero BuildConfig, got %+v", got)
	}
}

// A typo in a cap must not take the API server down, and must not be
// read as some other number.
func TestLoadBuildConfigIgnoresMalformedNumbers(t *testing.T) {
	for _, bad := range []string{"lots", "8GB", "-4", "8.5"} {
		cfg := config.NewEmpty()
		cfg.Set("HTTP_API_BUILD_MAX_CPUS", bad)
		got := loadBuildConfig(cfg, ccbTestLogger(t))
		if got.MaxCpus != 0 {
			t.Errorf("MaxCpus from %q = %d, want 0 (ignored)", bad, got.MaxCpus)
		}
	}
}
