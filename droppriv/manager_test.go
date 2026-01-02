package droppriv

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

func TestConfigFromHTCondor(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("DROP_PRIVILEGES", "true")
	cfg.Set("CONDOR_IDS", "42:84")
	cfg.Set("CONDOR_USER", "daemon")

	conf := ConfigFromHTCondor(cfg)

	if !conf.Enabled {
		t.Fatalf("expected drop privileges to be enabled")
	}
	if conf.CondorUser != "daemon" {
		t.Fatalf("expected condor user override, got %q", conf.CondorUser)
	}
	if conf.CondorIDs == nil {
		t.Fatalf("expected parsed condor IDs")
	}
	if conf.CondorIDs.UID != 42 || conf.CondorIDs.GID != 84 {
		t.Fatalf("unexpected condor IDs: %+v", conf.CondorIDs)
	}
}

func TestManagerOperationsDisabled(t *testing.T) {
	mgr, err := NewManager(Config{Enabled: false})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	baseDir := filepath.Join(t.TempDir(), "sandbox")
	if err := mgr.MkdirAll("", baseDir, 0o750); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	filePath := filepath.Join(baseDir, "test.txt")
	file, err := mgr.OpenFile("", filePath, os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	if _, err := file.WriteString("hello"); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	_ = file.Close()

	readFile, err := mgr.Open("", filePath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	data, err := io.ReadAll(readFile)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	_ = readFile.Close()

	if string(data) != "hello" {
		t.Fatalf("unexpected file contents: %q", string(data))
	}
}
