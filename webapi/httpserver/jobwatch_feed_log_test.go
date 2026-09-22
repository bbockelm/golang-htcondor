package httpserver

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// capturedFeedLog runs the connect log line against a buffer and returns
// the entry it produced.
func capturedFeedLog(t *testing.T, info *dbmirror.Info) logging.BufferEntry {
	t.Helper()
	buf := logging.NewBuffer(16, slog.LevelDebug)
	// DestinationHTTP is not at Info by default, and this line is the
	// thing under test.
	logger, err := logging.New(&logging.Config{
		OutputPath:   "stderr",
		DefaultLevel: logging.VerbosityInfo,
		DestinationLevels: map[logging.Destination]logging.Verbosity{
			logging.DestinationHTTP: logging.VerbosityInfo,
		},
	})
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}
	logging.AttachBuffer(logger, buf)

	h := &Handler{logger: logger}
	h.logJobWatchFeedConnected(info)

	entries := buf.Entries(16)
	for _, e := range entries {
		if strings.Contains(e.Message, "Following the htcondordb jobs table") {
			return e
		}
	}
	t.Fatalf("the connect line was not logged; got %d entries", len(entries))
	return logging.BufferEntry{}
}

// The line said only that the feed was following "the htcondordb jobs
// table", so answering "which htcondordb is this pod following?" meant
// cross-referencing /readyz -- or /api/v1/dbmirror/status, which is
// admin-gated. It carries the same two fields /readyz does.
func TestJobWatchFeedLogsWhichMirrorItFollows(t *testing.T) {
	entry := capturedFeedLog(t, &dbmirror.Info{
		Name:    "htcondordb@head04.af.uchicago.edu",
		Address: "<192.170.241.201:9618?sock=htcondordb>",
	})

	if got := entry.Fields["name"]; got != "htcondordb@head04.af.uchicago.edu" {
		t.Errorf("name = %q, want the mirror's advertised name", got)
	}
	if got := entry.Fields["address"]; got != "<192.170.241.201:9618?sock=htcondordb>" {
		t.Errorf("address = %q, want the address that was dialled", got)
	}
}

// An ad with no name is not a reason to log an empty one: a field that is
// present but blank reads as "the mirror is called nothing" rather than
// "this build could not tell you".
func TestJobWatchFeedOmitsUnknownIdentity(t *testing.T) {
	entry := capturedFeedLog(t, &dbmirror.Info{Address: "<10.0.0.1:9618>"})
	if _, ok := entry.Fields["name"]; ok {
		t.Errorf("logged a name field for an ad that carried none: %q", entry.Fields["name"])
	}
	if got := entry.Fields["address"]; got != "<10.0.0.1:9618>" {
		t.Errorf("address = %q, want the one fact it does have", got)
	}

	// And a nil Info must not panic the reconnect path it sits on.
	if e := capturedFeedLog(t, nil); e.Message == "" {
		t.Error("a nil Info produced no line at all")
	}
}
