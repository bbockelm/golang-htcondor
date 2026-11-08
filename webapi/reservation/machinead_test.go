package reservation

import (
	"strings"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"
)

// sieveSays evaluates the sieve the way a startd does: the machine ad
// as the scope, the job ad as TARGET.
func sieveSays(t *testing.T, machine, job *classad.ClassAd) classad.Value {
	t.Helper()
	expr, err := classad.ParseExpr(Sieve)
	if err != nil {
		t.Fatalf("the sieve does not parse: %v", err)
	}
	return machine.EvaluateExprWithTarget(expr, job)
}

func admits(t *testing.T, machine, job *classad.ClassAd) bool {
	t.Helper()
	// A value that is not true refuses the match: START has to evaluate
	// true for a slot's Requirements to be satisfied, so error and
	// undefined are refusals, not failures of this test.
	return sieveSays(t, machine, job).String() == "true"
}

func jobAd(attrs map[string]any) *classad.ClassAd {
	ad := classad.New()
	for k, v := range attrs {
		_ = ad.Set(k, v)
	}
	return ad
}

// TestSieve is the whole admission policy, read against the four
// situations an execute point is ever in.
func TestSieve(t *testing.T) {
	now := time.Now()
	bell := now.Add(4 * time.Hour)
	end := bell.Add(90 * time.Minute)

	draining := HoldAd(bell, end, "cs301")
	inWindow := HoldAd(now.Add(-time.Minute), end, "cs301")
	released := ReleaseAd()
	untouched := classad.New()

	cases := []struct {
		name    string
		machine *classad.ClassAd
		job     *classad.ClassAd
		want    bool
	}{
		{
			// Nothing has ever been pushed here. ReservationUntil
			// defaults to zero, which is always in the past.
			name:    "untouched machine takes anything",
			machine: untouched, job: jobAd(nil), want: true,
		},
		{
			// The refusal the whole drain rests on. An unstamped job is
			// not guessed about.
			name:    "draining refuses an unstamped job",
			machine: draining, job: jobAd(nil), want: false,
		},
		{
			name:    "draining admits a job that finishes before the bell",
			machine: draining,
			job:     jobAd(map[string]any{AttrBucket: Bucket(30 * time.Minute)}),
			want:    true,
		},
		{
			name:    "draining refuses a job that would still be running",
			machine: draining,
			job:     jobAd(map[string]any{AttrBucket: Bucket(12 * time.Hour)}),
			want:    false,
		},
		{
			// A job exactly as long as the time left is admitted: it
			// finishes at the bell, which is when the seat is wanted.
			name:    "draining admits a job that ends exactly at the bell",
			machine: draining,
			job:     jobAd(map[string]any{AttrBucket: int64(4 * 3600)}),
			want:    true,
		},
		{
			name:    "draining admits the reservation's own jobs",
			machine: draining,
			job:     jobAd(map[string]any{"ProjectName": "cs301"}),
			want:    true,
		},
		{
			// Past the bell nothing is admitted on an estimate, however
			// short: the seats are taken, not being drained towards.
			name:    "in the window, a short job of another project is refused",
			machine: inWindow,
			job:     jobAd(map[string]any{AttrBucket: Bucket(time.Minute), "ProjectName": "other"}),
			want:    false,
		},
		{
			name:    "in the window, the reservation's jobs are admitted",
			machine: inWindow,
			job:     jobAd(map[string]any{"ProjectName": "cs301"}),
			want:    true,
		},
		{
			name:    "released takes anything",
			machine: released, job: jobAd(nil), want: true,
		},
		{
			name:    "held for an empty project does not admit project-less jobs",
			machine: HoldAd(bell, end, ""),
			job:     jobAd(nil),
			want:    false,
		},
		{
			// The case the project guard exists for. With
			// ReservationProject absent rather than empty, the bare
			// comparison is undefined =?= undefined, which is TRUE --
			// so an unguarded sieve would admit every job that names no
			// project, which is most of them. An empty string does not
			// reproduce it: "" =?= undefined is false.
			name: "held with no project attribute at all refuses project-less jobs",
			machine: func() *classad.ClassAd {
				ad := HoldAd(bell, end, "cs301")
				ad.Delete(AttrProject)
				return ad
			}(),
			job:  jobAd(nil),
			want: false,
		},
		{
			// A job may carry anything in the attribute; the sieve must
			// not read a non-number as a short runtime.
			name:    "a non-numeric estimate is not admitted",
			machine: draining,
			job:     jobAd(map[string]any{AttrBucket: "soon"}),
			want:    false,
		},
		{
			name:    "a negative estimate is not admitted",
			machine: draining,
			job:     jobAd(map[string]any{AttrBucket: int64(-1)}),
			want:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := admits(t, tc.machine, tc.job); got != tc.want {
				t.Errorf("admitted = %v, want %v (sieve said %v)", got, tc.want, sieveSays(t, tc.machine, tc.job))
			}
		})
	}
}

// TestSieveUsesNoFunctions: the sieve is evaluated by HTCondor's C++
// ClassAds on the execute point and composed and tested by this Go
// implementation. The two do not offer the same function set -- strlen
// is in one and not the other -- and a sieve that parses differently in
// the two places is worse than a wordier one that parses the same.
func TestSieveUsesNoFunctions(t *testing.T) {
	// time() is the one exception: it is the only way to ask what the
	// clock says, and both implementations have it.
	rest := strings.ReplaceAll(Sieve, "time()", "")
	if i := strings.IndexByte(rest, '('); i >= 0 {
		// Every remaining '(' must be grouping, i.e. preceded by a
		// space or another opener, never by an identifier character.
		for j := range len(rest) {
			if rest[j] != '(' || j == 0 {
				continue
			}
			if c := rest[j-1]; c != ' ' && c != '(' {
				t.Errorf("the sieve appears to call a function near %q", rest[max(0, j-20):min(len(rest), j+2)])
			}
		}
	}
}

// TestSieveIsConstant: two controllers pushing the same machine at the
// same moment must push identical bytes, or one undoes the other.
func TestSieveIsConstant(t *testing.T) {
	a := HoldAd(time.Unix(1, 0), time.Unix(2, 0), "p")
	b := HoldAd(time.Unix(1, 0), time.Unix(2, 0), "p")
	ae, _ := a.Lookup(AttrStart)
	be, _ := b.Lookup(AttrStart)
	if ae.String() != be.String() {
		t.Errorf("two pushes composed different sieves:\n  %s\n  %s", ae, be)
	}
}

// TestHoldAdCarriesTheSieve: an execute point that restarted since the
// last push has forgotten everything. A hold that set only the operands
// would leave it unconstrained while the controller counted it held.
func TestHoldAdCarriesTheSieve(t *testing.T) {
	for name, ad := range map[string]*classad.ClassAd{
		"hold":    HoldAd(time.Now(), time.Now().Add(time.Hour), "cs301"),
		"release": ReleaseAd(),
		"probe":   ProbeAd(),
	} {
		if _, ok := ad.Lookup(AttrStart); !ok {
			t.Errorf("%s ad carries no %s", name, AttrStart)
		}
	}
}

// TestReleaseAdStopsConstraining: nothing can be deleted from a machine
// ad, so release has to write values that mean nothing rather than
// remove the ones that meant something.
func TestReleaseAdStopsConstraining(t *testing.T) {
	ad := ReleaseAd()
	for _, attr := range []string{AttrDeadline, AttrUntil} {
		if v, ok := ad.EvaluateAttrInt(attr); !ok || v != 0 {
			t.Errorf("%s = %v (present=%v), want 0", attr, v, ok)
		}
	}
	if v, ok := ad.EvaluateAttrString(AttrProject); !ok || v != "" {
		t.Errorf("%s = %q, want empty", AttrProject, v)
	}
}

// TestBucket rounds up, because the estimate is an upper bound and
// rounding down would admit a job that does not fit.
func TestBucket(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want int64
	}{
		{0, 1800},
		{-time.Hour, 1800},
		{time.Second, 1800},
		{30 * time.Minute, 1800},
		{30*time.Minute + time.Second, 3600},
		{90 * time.Minute, 5400},
		{24 * time.Hour, 86400},
	}
	for _, tc := range cases {
		if got := Bucket(tc.in); got != tc.want {
			t.Errorf("Bucket(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestHeldFromAd reads back what a machine is held for, which is how the
// controller learns what the pool actually is rather than what it
// remembers pushing.
func TestHeldFromAd(t *testing.T) {
	now := time.Unix(1_762_600_000, 0)
	cases := []struct {
		name string
		ad   *classad.ClassAd
		held bool
	}{
		{"untouched", classad.New(), false},
		{"released", ReleaseAd(), false},
		{
			"window already over",
			HoldAd(now.Add(-2*time.Hour), now.Add(-time.Hour), "cs301"),
			false,
		},
		{
			"draining",
			HoldAd(now.Add(time.Hour), now.Add(2*time.Hour), "cs301"),
			true,
		},
		{
			"in the window",
			HoldAd(now.Add(-time.Minute), now.Add(time.Hour), "cs301"),
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, project, held := HeldFromAd(tc.ad, now)
			if held != tc.held {
				t.Fatalf("held = %v, want %v", held, tc.held)
			}
			if held && project != "cs301" {
				t.Errorf("project = %q, want cs301", project)
			}
		})
	}
}

// TestProvisioned recognises a site's own spelling of the clause, since
// the attribute name is all that matters and ClassAd attribute names
// are case-insensitive.
func TestProvisioned(t *testing.T) {
	cases := map[string]bool{
		"":                               false,
		"TARGET.Owner == \"alice\"":      false,
		StartStanza:                      true,
		"(Foo) && (reservationstart?:1)": true,
		"ReservationStart":               true,
	}
	for start, want := range cases {
		if got := Provisioned(start); got != want {
			t.Errorf("Provisioned(%q) = %v, want %v", start, got, want)
		}
	}
}
