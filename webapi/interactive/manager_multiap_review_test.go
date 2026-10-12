package interactive

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A session this process placed on an AP that has since become
// unreachable keeps its name, though the catalog has not seen it: Create
// on another AP is refused naming it, the limit counts it, and the record
// is not displaced (so its lease expiry still goes to its AP).
func TestMultiAPUnreachableRecordedSessionKeepsItsName(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.lagging()
	aps.assign(testAP1)
	mgr, _ := multiManager(t, aps, Options{MaxPerOwner: 1})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	aps.running(testAP1)
	aps.setUnreachable(testAP1)

	_, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work", Schedd: testAP2})
	var exists *SessionExistsError
	if !errors.As(err, &exists) || exists.Info.Schedd != testAP1 || exists.Info.APError == "" {
		t.Fatalf("Create on %s = %v, want SessionExistsError for the unreachable session on %s", testAP2, err, testAP1)
	}
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "other", Schedd: testAP2}); err == nil ||
		!strings.Contains(err.Error(), "per-user limit") {
		t.Errorf("Create of another name = %v, want the per-user limit counting the unreachable session", err)
	}
	if n := len(aps.schedds[testAP2].submittedFiles()); n != 0 {
		t.Errorf("%s got %d submissions, want none", testAP2, n)
	}
	if sess := mgr.sessionFor(alice.Owner, "work"); sess == nil || sess.ap != testAP1 {
		t.Errorf("the record of %q is %+v, want it still on %s", "work", sess, testAP1)
	}
	infos, err := mgr.List(context.Background(), alice)
	if err != nil || len(infos) != 1 || infos[0].Schedd != testAP1 || infos[0].APError == "" {
		t.Errorf("List = %+v, %v; want the session on %s marked unreachable", infos, err, testAP1)
	}
}

// Find refuses a name on two APs rather than returning one of them.
func TestMultiAPFindRefusesAnAmbiguousName(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.injectSession(testAP1, 7, "work")
	aps.injectSession(testAP2, 7, "work")
	mgr, _ := multiManager(t, aps, Options{})
	info, err := mgr.Find(context.Background(), alice, "work")
	var amb *AmbiguousSessionError
	if !errors.As(err, &amb) || len(amb.Jobs) != 2 {
		t.Fatalf("Find = %+v, %v; want AmbiguousSessionError naming both", info, err)
	}
}

// Find reaches a session this process knows on its own AP without the
// catalog, so a hub outage does not lose it; FindOn asks that AP only.
func TestMultiAPFindReachesAKnownSessionWithTheHubDown(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.assign(testAP2)
	mgr, _ := multiManager(t, aps, Options{})
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "work"}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	aps.mu.Lock()
	aps.locateErr = errors.New("the federation hub is unavailable")
	locates := aps.locates
	aps.routes = nil
	aps.mu.Unlock()

	info, err := mgr.Find(context.Background(), alice, "work")
	if err != nil || info == nil || info.Schedd != testAP2 {
		t.Fatalf("Find with the hub down = %+v, %v; want the session on %s", info, err, testAP2)
	}
	again, err := mgr.FindOn(context.Background(), alice, info.Schedd, "work")
	if err != nil || again == nil || again.JobID != info.JobID {
		t.Fatalf("FindOn = %+v, %v", again, err)
	}
	aps.mu.Lock()
	gotLocates, routes := aps.locates, append([]string(nil), aps.routes...)
	aps.mu.Unlock()
	if gotLocates != locates {
		t.Errorf("the catalog was asked %d times for a session this process knows", gotLocates-locates)
	}
	for _, ap := range routes {
		if ap != testAP2 {
			t.Errorf("Find/FindOn reached %s", ap)
		}
	}
	// A name this process does not know needs the catalog.
	if _, err := mgr.Find(context.Background(), alice, "unknown"); err == nil {
		t.Error("Find of an unknown name with the hub down answered")
	}
}

// An AP that never answers is given up on within APTimeout and reported
// from what is known of it, rather than stalling the listing.
func TestMultiAPHangingAPIsTimedOut(t *testing.T) {
	aps := newFakeAPs(testAP1, testAP2)
	aps.injectSession(testAP1, 7, "a")
	aps.injectSession(testAP2, 8, "b")
	aps.hang = map[string]bool{testAP2: true}
	mgr, _ := multiManager(t, aps, Options{APTimeout: 200 * time.Millisecond})

	start := time.Now()
	infos, err := mgr.List(context.Background(), alice)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("List took %s with one AP hanging", elapsed)
	}
	if err != nil || len(infos) != 2 {
		t.Fatalf("List = %+v, %v; want both sessions", infos, err)
	}
	for _, info := range infos {
		switch info.Schedd {
		case testAP1:
			if info.APError != "" {
				t.Errorf("%s's session marked unreachable: %s", testAP1, info.APError)
			}
		case testAP2:
			if !strings.Contains(info.APError, "deadline") {
				t.Errorf("%s's session APError = %q, want the timeout", testAP2, info.APError)
			}
		}
	}
	if _, err := mgr.Create(context.Background(), alice, CreateSpec{Name: "b", Schedd: testAP1}); err == nil {
		t.Error("Create of the name held on the hanging AP succeeded")
	}
}
