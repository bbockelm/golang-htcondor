package daemon

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
)

func TestExtractDestination(t *testing.T) {
	cases := []struct {
		name     string
		args     []any
		wantDest logging.Destination
		wantArgs []any
	}{
		{"absent", []any{"k", "v"}, logging.DestinationGeneral, []any{"k", "v"}},
		{"cedar", []any{"destination", "cedar", "k", "v"}, logging.DestinationCedar, []any{"k", "v"}},
		{"cedar-middle", []any{"a", 1, "destination", "cedar"}, logging.DestinationCedar, []any{"a", 1}},
		{"unknown-string", []any{"destination", "bogus", "k", "v"}, logging.DestinationGeneral, []any{"k", "v"}},
		{"dangling-key", []any{"k", "v", "odd"}, logging.DestinationGeneral, []any{"k", "v", "odd"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest, args := extractDestination(tc.args)
			if dest != tc.wantDest {
				t.Errorf("dest = %v, want %v", dest, tc.wantDest)
			}
			if len(args) != len(tc.wantArgs) {
				t.Fatalf("args = %v, want %v", args, tc.wantArgs)
			}
			for i := range args {
				if args[i] != tc.wantArgs[i] {
					t.Errorf("args[%d] = %v, want %v", i, args[i], tc.wantArgs[i])
				}
			}
		})
	}
}

// TestSlogBridgeRoutesDestination is the regression for the duplicate-log bug: a plain-slog
// caller (like cedar) that tags a record destination=cedar must (1) be routed to the cedar
// destination — so its default Warn level suppresses Info chatter — and (2) never produce a
// record carrying two destination attributes.
func TestSlogBridgeRoutesDestination(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bridge.log")
	l, err := logging.New(&logging.Config{
		OutputPath:        path,
		SkipGlobalInstall: true,
		DestinationLevels: map[logging.Destination]logging.Verbosity{logging.DestinationCedar: logging.VerbosityWarn},
		DefaultLevel:      logging.VerbosityInfo,
	})
	if err != nil {
		t.Fatal(err)
	}
	sl := slog.New(&slogBridge{log: l})

	// Cedar Info -> routed to cedar (Warn) -> suppressed, exactly as in production where the
	// bug let this handshake chatter leak into the General stream.
	sl.Info("cedar session resumed", "destination", "cedar")
	// General Info -> logged, with a single destination attribute.
	sl.Info("general startup", "destination", "general", "k", "v")
	// Cedar Warn -> logged (at/above its level).
	sl.Warn("cedar warning", "destination", "cedar")

	out := readFile(t, path)

	if strings.Contains(out, "cedar session resumed") {
		t.Errorf("cedar Info leaked past the Warn suppression:\n%s", out)
	}
	if !strings.Contains(out, "general startup") {
		t.Errorf("general Info missing:\n%s", out)
	}
	if !strings.Contains(out, "cedar warning") {
		t.Errorf("cedar Warn missing:\n%s", out)
	}
	// No record may carry two destination attributes (the reported symptom).
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.Count(line, "destination=") > 1 {
			t.Errorf("line has duplicate destination attributes: %q", line)
		}
	}
	// The general line must be tagged cedar-free and general-tagged.
	if !strings.Contains(out, "destination=general") {
		t.Errorf("general line not tagged destination=general:\n%s", out)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
