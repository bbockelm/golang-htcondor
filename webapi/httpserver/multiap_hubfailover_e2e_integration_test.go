//go:build integration

package httpserver

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/watchpoll"
)

// Two federation hubs, end to end: the stack TestMultiAPEndToEnd builds,
// with a second hub fed from the same two spokes, and the API server
// discovering both through the collector. The hub reads go to is
// stopped:
//
//   - reads continue from the other hub within a bounded time, naming it;
//   - a watch over jobs that stay queued does not fire across the switch
//     (they are on the new hub too, but the evaluator's evidence starts
//     over there);
//   - a job that completes after the switch fires its watch.
func TestMultiAPHubFailoverEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test (runs two schedds, four htcondordb daemons and an API server)")
	}
	bin := htcondordbBinary(t)
	if os.Geteuid() == 0 {
		t.Skip("schedd sync refuses to run as root; run this test as an ordinary user")
	}
	started := time.Now()
	s := startMultiAPStackWith(t, bin, multiAPStackOptions{secondHub: true})
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
		{"both hubs are discovered and reachable, one active", e2eBothHubsKnown},
		{"watches register on the active hub", e2eFailoverRegisterWatches},
		{"stopping the active hub moves reads to the other", e2eStopActiveHub},
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
	// active and other are the hubs' names before the switch.
	active, other string
	// queuedURL watches 2.0 on both APs, which stay idle; runURL watches
	// 1.0 on both, of which ap1's runs after the switch.
	queuedURL, runURL string
}

// proc returns the hub process advertising name.
func (f *e2eHubFailover) proc(t *testing.T, name string) *htcondordbProc {
	t.Helper()
	switch name {
	case "hub@127.0.0.1":
		return f.s.hub
	case "hub2@127.0.0.1":
		return f.s.hub2
	}
	t.Fatalf("no hub process advertises %q", name)
	return nil
}

// e2eBothHubsKnown: /api/v1/aps lists both hubs, both reachable with
// both APs fresh, and one of them active.
func e2eBothHubsKnown(t *testing.T, f *e2eHubFailover) {
	var aps APsResponse
	waitFor(t, "both hubs to be discovered and to hold both APs fresh", 90*time.Second, func() bool {
		aps = f.s.aps(t)
		if len(aps.Hubs) != 2 {
			return false
		}
		for _, h := range aps.Hubs {
			if !h.Reachable || h.FreshAPs != 2 {
				return false
			}
		}
		return true
	})
	if !aps.Hub.Active || aps.Hub.Name == "" || aps.Sources.Hub != aps.Hub.Name {
		t.Fatalf("active hub %+v, sources from %q", aps.Hub, aps.Sources.Hub)
	}
	f.active = aps.Hub.Name
	for _, h := range aps.Hubs {
		if h.Name != f.active {
			f.other = h.Name
		}
	}
	t.Logf("active hub %s, peer %s", f.active, f.other)
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

// e2eStopActiveHub: the active hub stops; reads come from the other,
// naming it, within a bounded time, with both APs still fresh.
func e2eStopActiveHub(t *testing.T, f *e2eHubFailover) {
	stopped := time.Now()
	f.proc(t, f.active).Stop()
	l := f.s.waitList(t, "reads to come from "+f.other, 60*time.Second, f.s.me, func(l e2eList) bool {
		return l.Sources.Hub == f.other && l.Sources.Fresh == 2 && len(l.keys()) >= len(e2eMine)
	})
	t.Logf("reads moved from %s to %s %s after it stopped", f.active, f.other, time.Since(stopped).Round(100*time.Millisecond))
	for _, k := range e2eMine {
		if !containsJob(l.keys(), k) {
			t.Errorf("%s missing from %s's listing", k, f.other)
		}
	}
	aps := f.s.aps(t)
	if aps.Hub.Name != f.other || aps.HubSwitch == nil || aps.HubSwitch.Reason != "unreachable" ||
		aps.HubSwitch.From != f.active || aps.HubSwitch.To != f.other {
		t.Fatalf("after the switch: hub %+v, switch %+v", aps.Hub, aps.HubSwitch)
	}
	if code, body := f.s.get(t, "", "/readyz"); code != 200 {
		t.Fatalf("readyz with one hub answering = %d %s", code, body)
	}
}

// e2eQueuedWatchHolds: the jobs the queued watch tracks never left; the
// evaluator runs passes on the new hub (a waiting poll is passes held
// open) and nothing fires.
func e2eQueuedWatchHolds(t *testing.T, f *e2eHubFailover) {
	if a := f.poll(t, f.queuedURL, 10*time.Second); a.State != watchpoll.StateWaiting || a.Selected != 2 {
		t.Fatalf("the queued watch across the switch = %+v, want still waiting on both 2.0s", a)
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
		a = f.poll(t, f.runURL, 60*time.Second)
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
