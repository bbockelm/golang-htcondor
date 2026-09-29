package htcondor

import (
	"testing"

	"github.com/bbockelm/cedar/commands"
)

func TestStartdHistoryEndpoint(t *testing.T) {
	sd := NewStartd("slot1@ep.example", "<10.0.0.1:9618>")
	if sd.Name() != "slot1@ep.example" || sd.Address() != "<10.0.0.1:9618>" {
		t.Fatalf("accessors wrong: %q %q", sd.Name(), sd.Address())
	}
	e := sd.historyEndpoint()
	// The startd serves history on GET_HISTORY, not the schedd's QUERY_SCHEDD_HISTORY: sending
	// the schedd command to a startd reaches a different handler entirely.
	if e.command != commands.GET_HISTORY {
		t.Errorf("command = %d, want GET_HISTORY (%d)", e.command, commands.GET_HISTORY)
	}
	if e.address != sd.Address() {
		t.Errorf("address = %q, want %q", e.address, sd.Address())
	}
	if e.daemon != "startd" {
		t.Errorf("daemon = %q, want startd", e.daemon)
	}
	if e.rateLimit != nil {
		t.Error("startd history should not borrow the schedd rate limiter")
	}
}

func TestScheddHistoryEndpointCommand(t *testing.T) {
	e := NewSchedd("s", "<10.0.0.2:9618>").historyEndpoint()
	if e.command != commands.QUERY_SCHEDD_HISTORY {
		t.Errorf("command = %d, want QUERY_SCHEDD_HISTORY (%d)", e.command, commands.QUERY_SCHEDD_HISTORY)
	}
	if e.daemon != "schedd" {
		t.Errorf("daemon = %q, want schedd", e.daemon)
	}
}

func TestStartdOptionsForceSource(t *testing.T) {
	in := &HistoryQueryOptions{
		Source:     HistorySourceJobHistory,
		Limit:      7,
		Since:      "CompletionDate < 1700000000",
		Projection: []string{"*"},
		Backwards:  true,
	}
	out := startdOptions(in)
	if out.Source != HistorySourceStartd {
		t.Errorf("Source = %q, want %q", out.Source, HistorySourceStartd)
	}
	if out.Limit != 7 || out.Since != in.Since || len(out.Projection) != 1 || !out.Backwards {
		t.Errorf("caller options not preserved: %+v", out)
	}
	if in.Source != HistorySourceJobHistory {
		t.Error("startdOptions must not mutate the caller's options")
	}

	// A nil options argument is the "everything default" case.
	if got := startdOptions(nil); got.Source != HistorySourceStartd {
		t.Errorf("startdOptions(nil).Source = %q, want %q", got.Source, HistorySourceStartd)
	}
}

func TestCreateHistoryQueryAdStartdSource(t *testing.T) {
	opts := (&HistoryQueryOptions{
		Source:     HistorySourceStartd,
		Limit:      -1,
		Since:      "CompletionDate < 1700000000",
		Projection: []string{"*"},
		Backwards:  true,
	}).ApplyDefaults()
	ad, err := createHistoryQueryAd("Owner == \"alice\"", &opts)
	if err != nil {
		t.Fatal(err)
	}
	// The record source is what makes the startd read STARTD_HISTORY (the helper builds the
	// search knob as <source>_HISTORY); without it the query reads the wrong file or fails.
	if src, _ := ad.EvaluateAttrString("HistoryRecordSource"); src != "STARTD" {
		t.Errorf("HistoryRecordSource = %q, want STARTD", src)
	}
	if _, ok := ad.Lookup("Since"); !ok {
		t.Error("Since not set on the query ad")
	}
	if _, ok := ad.Lookup("Requirements"); !ok {
		t.Error("constraint not set on the query ad")
	}
	// Projection "*" means "every attribute", which the wire form expresses by sending none.
	if _, ok := ad.Lookup("Projection"); ok {
		t.Error("Projection should be absent when every attribute is requested")
	}
}

func TestParseSinceExpr(t *testing.T) {
	if _, err := parseSinceExpr("CompletionDate < 1700000000"); err != nil {
		t.Errorf("expression since: %v", err)
	}
	if _, err := parseSinceExpr("nope nope"); err == nil {
		t.Error("unparseable since should error")
	}
	expr, err := parseSinceExpr("123")
	if err != nil {
		t.Fatalf("cluster id since: %v", err)
	}
	if expr == nil {
		t.Fatal("cluster id since returned a nil expression")
	}
}
