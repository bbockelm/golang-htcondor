//go:build integration

package httpserver

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/watchpoll"
)

// Two federation hubs, end to end: the stack TestMultiAPEndToEnd builds,
// with a standby hub that federates ap1 only, and the API server
// discovering both through the collector. The full hub, which reads go
// to, is stopped:
//
//   - reads continue from the standby within a bounded time, naming it,
//     with ap1 settling and ap2 absent;
//   - a watch over jobs that stay queued -- 2.0 on both APs -- does not
//     fire across the switch, though ap2's 2.0 is missing from the
//     standby, for longer than the absence horizon;
//   - a job that completes after the switch fires its watch.
const (
	e2eFullHub    = "hub@127.0.0.1"
	e2eStandbyHub = "standby@127.0.0.1"
	// e2eAbsenceHorizon outlasts how long after a sighting an absence
	// can first count: the reported staleness, the hub's minute of row
	// refresh and a state interval.
	e2eAbsenceHorizon = 80 * time.Second
)

func TestMultiAPHubFailoverEndToEnd(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("integration test (runs two schedds, four htcondordb daemons and an API server)")
	}
	bin := htcondordbBinary(t)
	if os.Geteuid() == 0 {
		t.Skip("schedd sync refuses to run as root; run this test as an ordinary user")
	}
	started := time.Now()
	s := startMultiAPStackWith(t, bin, multiAPStackOptions{secondHub: `regexp("^ap1@", Name)`})
	s.waitList(t, "both APs' jobs to reach the API, with both APs fresh", 90*time.Second, s.me, func(l e2eList) bool {
		for _, k := range e2eMine {
			if !containsJob(l.keys(), k) {
				return false
			}
		}
		return l.Sources.APs == 2 && l.Sources.Fresh == 2
	})
	t.Logf("stack up in %s", time.Since(started).Round(time.Second))

	f := &e2eHubFailover{e2eWatches: &e2eWatches{s: s, token: s.mintToken(t, s.me)}}
	for _, phase := range []struct {
		name string
		run  func(*testing.T, *e2eHubFailover)
	}{
		{"both hubs are discovered, the full one active", e2eBothHubsKnown},
		{"watches register on the full hub", e2eFailoverRegisterWatches},
		{"stopping the full hub moves reads to the standby", e2eStopActiveHub},
		{"a watch over queued jobs does not fire across the switch", e2eQueuedWatchHolds},
		{"a job that completes after the switch fires its watch", e2eCompletesAfterSwitch},
	} {
		if !t.Run(phase.name, func(t *testing.T) { phase.run(t, f) }) {
			break
		}
	}
	if n := s.srv.multi.scheddCalls.Load(); n != 0 {
		t.Errorf("the single-schedd accessor was called %d times in multi-AP mode", n)
	}
	t.Logf("total %s", time.Since(started).Round(time.Second))
}

type e2eHubFailover struct {
	*e2eWatches
	// queuedURL watches 2.0 on both APs, which stay idle; runURL watches
	// 1.0 on both, of which ap1's runs after the switch.
	queuedURL, runURL string
}

// e2eBothHubsKnown: /api/v1/aps lists both hubs, reachable; the full hub
// holds both APs fresh and is active, the standby holds ap1.
func e2eBothHubsKnown(t *testing.T, f *e2eHubFailover) {
	var aps APsResponse
	waitFor(t, "both hubs to be discovered, the full one active with both APs fresh", 150*time.Second, func() bool {
		aps = f.s.aps(t)
		if len(aps.Hubs) != 2 || aps.Hub.Name != e2eFullHub {
			return false
		}
		for _, h := range aps.Hubs {
			want := 2
			if h.Name == e2eStandbyHub {
				want = 1
			}
			if !h.Reachable || h.FreshAPs != want {
				return false
			}
		}
		return true
	})
	if !aps.Hub.Active || aps.Sources.Hub != e2eFullHub {
		t.Fatalf("active hub %+v, sources from %q", aps.Hub, aps.Sources.Hub)
	}
}

func (f *e2eHubFailover) registerOn(t *testing.T, label, constraint string) string {
	t.Helper()
	sc := f.call(t, "watch_jobs", map[string]any{"constraint": constraint, "event": "done", "mode": "any", "label": label})
	id, _ := sc["watch_id"].(string)
	if id == "" || sc["fired"] == true {
		t.Fatalf("watch_jobs %s: %v", label, sc)
	}
	u, _ := f.call(t, "create_watch_url", map[string]any{"watch_id": id})["url"].(string)
	if u == "" {
		t.Fatalf("create_watch_url for %s returned no URL", id)
	}
	if a := f.poll(t, u, 0); a.State != watchpoll.StateWaiting || a.Selected != 2 {
		t.Fatalf("watch %s = %+v, want waiting on a job on each AP", label, a)
	}
	return u
}

func e2eFailoverRegisterWatches(t *testing.T, f *e2eHubFailover) {
	f.queuedURL = f.registerOn(t, "queued", "ClusterId == 2")
	f.runURL = f.registerOn(t, "run", "ClusterId == 1")
}

// e2eStopActiveHub: the full hub stops; reads come from the standby,
// naming it, within a bounded time: ap1's jobs, ap1 settling (just
// switched) and ap2 absent.
func e2eStopActiveHub(t *testing.T, f *e2eHubFailover) {
	stopped := time.Now()
	f.s.hub.Stop()
	l := f.s.waitList(t, "reads to come from "+e2eStandbyHub, 60*time.Second, f.s.me, func(l e2eList) bool {
		return l.Sources.Hub == e2eStandbyHub && containsJob(l.keys(), e2eAP1Job1) && containsJob(l.keys(), e2eAP1Job2)
	})
	t.Logf("reads moved from %s to %s %s after it stopped", e2eFullHub, e2eStandbyHub, time.Since(stopped).Round(100*time.Millisecond))
	if st := l.Sources.StateOf(e2eAP1); st != multiap.StateSettling && st != multiap.StateFresh {
		t.Errorf("%s on the standby is %q, want settling (or fresh once settled)", e2eAP1, st)
	}
	if st := l.Sources.StateOf(e2eAP2); st != multiap.StateAbsent {
		t.Errorf("%s on the standby is %q, want absent", e2eAP2, st)
	}
	if containsJob(l.keys(), e2eAP2Job2) {
		t.Errorf("%s listed from a standby that does not federate %s", e2eAP2Job2, e2eAP2)
	}
	aps := f.s.aps(t)
	if aps.Hub.Name != e2eStandbyHub || aps.HubSwitch == nil || aps.HubSwitch.Reason != "unreachable" ||
		aps.HubSwitch.From != e2eFullHub || aps.HubSwitch.To != e2eStandbyHub {
		t.Fatalf("after the switch: hub %+v, switch %+v", aps.Hub, aps.HubSwitch)
	}
	if code, body := f.s.get(t, "", "/readyz"); code != 200 {
		t.Fatalf("readyz with one hub answering = %d %s", code, body)
	}
}

// e2eQueuedWatchHolds: the jobs the queued watch tracks never left, but
// ap2's 2.0 is missing from the standby. Passes run on the standby (a
// waiting poll is passes held open) for longer than the absence
// horizon, and nothing fires.
func e2eQueuedWatchHolds(t *testing.T, f *e2eHubFailover) {
	for start := time.Now(); time.Since(start) < e2eAbsenceHorizon; {
		// Under the server's 30 s write timeout.
		if a := f.poll(t, f.queuedURL, 20*time.Second); a.State != watchpoll.StateWaiting || a.Selected != 2 {
			t.Fatalf("the queued watch %s after the switch = %+v, want still waiting on both 2.0s",
				time.Since(start).Round(time.Second), a)
		}
	}
	if a := f.poll(t, f.runURL, 0); a.State != watchpoll.StateWaiting {
		t.Fatalf("the run watch = %+v before anything ran", a)
	}
}

// e2eCompletesAfterSwitch: ap1's 1.0 runs and finishes after the switch;
// its watch fires naming it alone, and the queued watch still waits.
func e2eCompletesAfterSwitch(t *testing.T, f *e2eHubFailover) {
	s := f.s
	s.condor(t, "condor_qedit", "-name", e2eAP1, "1.0", "Args", `"2"`)
	s.condor(t, "condor_qedit", "-name", e2eAP1, "1.0", "E2ERun", "true")
	ran := time.Now()
	var a watchpoll.Answer
	deadline := time.Now().Add(4 * time.Minute)
	for a.State != watchpoll.StateFired && time.Now().Before(deadline) {
		a = f.poll(t, f.runURL, 20*time.Second)
	}
	if a.State != watchpoll.StateFired {
		t.Fatalf("the run watch did not fire after %s completed: %+v", e2eAP1Job1, a)
	}
	t.Logf("fired %s after the job was released to run", time.Since(ran).Round(time.Second))
	var got []string
	for _, m := range a.Matched {
		got = append(got, fmt.Sprintf("%d.%d@%s", m.Cluster, m.Proc, m.Schedd))
	}
	if len(got) != 1 || got[0] != e2eAP1Job1.String() {
		t.Fatalf("fired for %s, want %s alone", strings.Join(got, ", "), e2eAP1Job1)
	}
	if b := f.poll(t, f.queuedURL, 0); b.State != watchpoll.StateWaiting {
		t.Fatalf("the queued watch = %+v after an unrelated job finished", b)
	}
}
