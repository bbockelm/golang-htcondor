package httpserver

import (
	"context"
	"net/http"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// Testing the mirror from the admin page exists because the status card
// answers "is it healthy" and an operator debugging one that is not
// needs "what happens when you actually try". Those differ: discovery
// can succeed against a collector ad for a database this daemon cannot
// authenticate to, and the background poller only re-checks on its own
// cadence, so a fix applied at the mirror is invisible here for up to an
// interval.
//
// The query is deliberately one that matches nothing. It exercises every
// stage a real read uses -- discover, dial, authenticate, execute -- and
// moves no rows, so it can be pressed repeatedly while chasing a
// misconfiguration without loading the database or the page.

// dbMirrorTestStage is one step of the probe, reported separately
// because that is the whole diagnostic value: "it failed" is what the
// card already said, and WHERE it failed is what an operator cannot get
// from anywhere else.
type dbMirrorTestStage struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	// Detail is the outcome in a form worth reading: the mirror found,
	// the address dialed, the row count. Empty when there is nothing to
	// add beyond OK.
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
	// Millis is how long the stage took. A dial that takes ten seconds
	// and then succeeds is a different problem from one that fails.
	Millis int64 `json:"millis"`
}

// dbMirrorRouting is what a real read would decide about this mirror,
// per kind of read.
//
// Reachability and usability are different questions and the probe only
// answered the first. Every stage could pass -- discovery finds the ad,
// the dial authenticates, the query returns -- while every real read
// declines the mirror on freshness and goes to the schedd, because the
// stages walk the connection and nothing walks the gate.
//
// That is not hypothetical: a projected collector read once stripped the
// sync attributes out of the ad, so JobQueueLastSyncTime was zero and
// live job reads all declined with "never synced" while this probe
// reported three green stages.
type dbMirrorRouting struct {
	// Kind is the read this decision governs: "jobs", "history" or
	// "epoch".
	Kind string `json:"kind"`
	// Use is whether a read of that kind would be served from the
	// mirror right now.
	Use bool `json:"use"`
	// Reason is the machine-readable decision code, and Note the
	// sentence behind it -- the same pair routing records in its
	// counters, so this page and those agree by construction.
	Reason string `json:"reason"`
	Note   string `json:"note,omitempty"`
}

type dbMirrorTestResponse struct {
	OK     bool                `json:"ok"`
	Stages []dbMirrorTestStage `json:"stages"`
	// Routing is what a real read would do with this mirror, which the
	// stages above cannot say. Empty when the probe never got far enough
	// to have an ad to judge.
	Routing []dbMirrorRouting `json:"routing,omitempty"`
	// Constraint is echoed so the page can show what was actually asked.
	Constraint string `json:"constraint"`
	TotalMs    int64  `json:"total_millis"`
}

// routingFor evaluates the gates a real read uses, against the ad the
// probe just discovered.
//
// The same functions the read paths call, not a copy of their rules: a
// second implementation here would be free to disagree with the one that
// decides, which is the failure this whole panel exists to catch.
func routingFor(info *dbmirror.Info) []dbMirrorRouting {
	if info == nil {
		return nil
	}
	decisions := []struct {
		kind string
		d    dbmirror.Decision
	}{
		// No page token and no history options: the plain shape of each
		// read, since the probe is asking about the mirror rather than
		// about one caller's query.
		{"jobs", dbmirror.JobsDecision(info, "")},
		{"history", dbmirror.HistoryDecision(info, nil)},
		{"epoch", dbmirror.EpochDecision(info)},
	}
	out := make([]dbMirrorRouting, 0, len(decisions))
	for _, e := range decisions {
		out = append(out, dbMirrorRouting{
			Kind:   e.kind,
			Use:    e.d.Use,
			Reason: string(e.d.Reason),
			Note:   e.d.Note,
		})
	}
	return out
}

// dbMirrorTestConstraint matches nothing, on purpose.
const dbMirrorTestConstraint = "false"

// dbMirrorTestTimeout bounds the whole probe. It is generous compared
// with a healthy round trip and short enough that a wedged mirror
// returns a page rather than a spinner.
const dbMirrorTestTimeout = 15 * time.Second

// handleDBMirrorTest runs one end-to-end probe of the mirror and reports
// each stage.
func (s *Handler) handleDBMirrorTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.requireAdmin(w, r) {
		return
	}
	if !s.dbMirror.Enabled() {
		s.writeJSON(w, http.StatusOK, dbMirrorTestResponse{
			Constraint: dbMirrorTestConstraint,
			Stages: []dbMirrorTestStage{{
				Name:  "configured",
				Error: "htcondordb routing is not configured: it needs both a collector to discover through and the HTCondor config whose SEC_* settings authenticate the connection",
			}},
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), dbMirrorTestTimeout)
	defer cancel()
	s.writeJSON(w, http.StatusOK, s.probeDBMirror(ctx))
}

// probeDBMirror walks the stages a real read walks. Split out so a test
// can drive it without an HTTP request.
func (s *Handler) probeDBMirror(ctx context.Context) dbMirrorTestResponse {
	return s.probeDBMirrorWith(ctx, s.dbMirror.Discover)
}

// probeDBMirrorWith is probeDBMirror with discovery injectable.
//
// The seam exists because the interesting half cannot be reached
// otherwise: routing is judged off a discovered ad, and a unit test has
// no mirror to discover. Without it the only testable path is the one
// where discovery fails, which is the path that reports nothing.
func (s *Handler) probeDBMirrorWith(ctx context.Context, discover func(context.Context) (*dbmirror.Info, error)) dbMirrorTestResponse {
	out := dbMirrorTestResponse{Constraint: dbMirrorTestConstraint}
	total := time.Now()
	defer func() { out.TotalMs = time.Since(total).Milliseconds() }()

	// Discovery is asked directly rather than read from the poller's
	// cache: an operator pressing this has usually just changed
	// something, and reporting a cached answer would show them the state
	// before their fix.
	step := time.Now()
	info, err := discover(ctx)
	stage := dbMirrorTestStage{Name: "discover", Millis: time.Since(step).Milliseconds()}
	if err != nil {
		stage.Error = err.Error()
		out.Stages = append(out.Stages, stage)
		return out
	}
	stage.OK = true
	stage.Detail = info.Name + " at " + info.Address
	out.Stages = append(out.Stages, stage)

	// Judged off the ad discovery just returned, before the connection
	// is attempted: the decision depends on what the mirror advertises,
	// not on whether this probe could reach it, and reporting it even
	// when a later stage fails is the more useful order.
	out.Routing = routingFor(info)

	step = time.Now()
	dbc, closer, _, err := s.dbMirror.Client(ctx)
	stage = dbMirrorTestStage{Name: "connect", Millis: time.Since(step).Milliseconds()}
	if err != nil {
		stage.Error = err.Error()
		out.Stages = append(out.Stages, stage)
		return out
	}
	defer closer()
	stage.OK = true
	stage.Detail = "authenticated"
	out.Stages = append(out.Stages, stage)

	step = time.Now()
	rows, err := dbc.QueryRawProject(ctx, "jobs", dbMirrorTestConstraint, []string{"ClusterId"}, 1)
	stage = dbMirrorTestStage{Name: "query", Millis: time.Since(step).Milliseconds()}
	if err != nil {
		stage.Error = err.Error()
		out.Stages = append(out.Stages, stage)
		return out
	}
	stage.OK = true
	stage.Detail = "the jobs table answered; a constraint matching nothing returned " + plural(len(rows), "row")
	out.Stages = append(out.Stages, stage)

	out.OK = true
	return out
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return itoa(n) + " " + noun + "s"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
