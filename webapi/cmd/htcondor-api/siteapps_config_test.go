package main

import (
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

func siteAppsTestLogger(t *testing.T) *logging.Logger {
	t.Helper()
	lg, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return lg
}

// The browser harness points a throwaway demo server at a bundle
// directory with _CONDOR_HTTP_API_SITE_APPS_DIR rather than writing a
// configuration file. That only works because config.New applies
// environment overrides, so this pins it: if the override path ever
// stops reaching here, the e2e suite would otherwise fail with "the app
// is not published" and no clue why.
func TestSiteAppsConfigReadsEnvironmentOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("_CONDOR_HTTP_API_SITE_APPS_DIR", dir)
	t.Setenv("_CONDOR_HTTP_API_SITE_APPS_RELOAD_INTERVAL", "2s")

	cfg, err := config.New()
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	got := loadSiteAppsConfig(cfg, siteAppsTestLogger(t))
	gotDir, gotReload := got.Dir, got.Reload

	if gotDir != dir {
		t.Errorf("dir = %q, want %q", gotDir, dir)
	}
	if gotReload != 2*time.Second {
		t.Errorf("reload = %v, want 2s", gotReload)
	}
}

// Unset means the feature is off, not a default directory.
func TestSiteAppsConfigUnsetIsEmpty(t *testing.T) {
	t.Setenv("_CONDOR_HTTP_API_SITE_APPS_DIR", "")
	cfg, err := config.New()
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	if gotDir := loadSiteAppsConfig(cfg, siteAppsTestLogger(t)).Dir; gotDir != "" {
		t.Errorf("dir = %q, want empty", gotDir)
	}
}

// A malformed interval falls back to the default rather than failing
// startup: an operator who typed "30" instead of "30s" should get a
// working server and a log line, not a daemon that will not come up.
func TestSiteAppsConfigRejectsBadInterval(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("_CONDOR_HTTP_API_SITE_APPS_DIR", dir)
	for _, bad := range []string{"30", "soon", "-5s", "0s"} {
		t.Setenv("_CONDOR_HTTP_API_SITE_APPS_RELOAD_INTERVAL", bad)
		cfg, err := config.New()
		if err != nil {
			t.Fatalf("config.New: %v", err)
		}
		gotReload := loadSiteAppsConfig(cfg, siteAppsTestLogger(t)).Reload
		if gotReload != 0 {
			t.Errorf("interval %q produced %v, want 0 so the default applies", bad, gotReload)
		}
	}
}

// Upload is off unless the site turns it on. An uploaded app runs with
// the rights of everyone who opens it, so the default has to be the
// safe one -- and a default that drifted to true would be invisible
// until somebody used it.
func TestSiteAppUploadIsOffByDefault(t *testing.T) {
	t.Setenv("_CONDOR_HTTP_API_SITE_APPS_DIR", t.TempDir())
	cfg, err := config.New()
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	if upload := loadSiteAppsConfig(cfg, siteAppsTestLogger(t)).Upload; upload {
		t.Error("upload is enabled without HTTP_API_SITE_APPS_UPLOAD")
	}

	t.Setenv("_CONDOR_HTTP_API_SITE_APPS_UPLOAD", "true")
	cfg, err = config.New()
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	if upload := loadSiteAppsConfig(cfg, siteAppsTestLogger(t)).Upload; !upload {
		t.Error("HTTP_API_SITE_APPS_UPLOAD = true did not enable upload")
	}
}

// Startup reads configuration before it can build a logger, so the
// helpers that do the reading get a nil one. This one logs what it
// found, and a nil *Logger used to be a SIGSEGV: setting a site-apps
// directory on a real server crash-looped it at startup, and the
// existing coverage missed it only because every case above hands in a
// real logger.
//
// It is not enough to call it with no directory configured -- the log
// line is inside the branch that a configured directory takes.
func TestSiteAppsConfigSurvivesANilLogger(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("_CONDOR_HTTP_API_SITE_APPS_DIR", dir)
	t.Setenv("_CONDOR_HTTP_API_SITE_APPS_RELOAD_INTERVAL", "not a duration")
	t.Setenv("_CONDOR_HTTP_API_SITE_APPS_UPLOAD", "true")

	cfg, err := config.New()
	if err != nil {
		t.Fatalf("config.New: %v", err)
	}
	// Every logging branch at once: the directory line, the bad-duration
	// error, and the upload-enabled line.
	got := loadSiteAppsConfig(cfg, nil)
	gotDir, gotReload, gotUpload := got.Dir, got.Reload, got.Upload

	if gotDir != dir {
		t.Errorf("dir = %q, want %q", gotDir, dir)
	}
	if gotReload != 0 {
		t.Errorf("reload = %v, want the default for an unparseable value", gotReload)
	}
	if !gotUpload {
		t.Error("upload is off")
	}
}
