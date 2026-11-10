package reservation

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"
)

// alwaysSpec is an always-on reservation with a submit file that
// renders, which is the only kind PlanClaims acts on.
func claimSpec(id string, seats int) *Spec {
	return &Spec{
		ID: id, Owner: "ada@example.org", Project: "cs301",
		Submit:  "executable = /bin/sleep\narguments = 1\nrequest_cpus = 2\nrequest_memory = 512\nqueue\n",
		Seats:   seats,
		Kind:    KindAlways,
		Enabled: true,
	}
}

func claimIDs(p ClaimPlan) []int64 {
	out := append([]int64(nil), p.Remove...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// A reservation with nothing held asks for one claim per seat.
func TestPlanClaimsAsksForOnePerSeat(t *testing.T) {
	plan := PlanClaims([]*Spec{claimSpec("cs301-lab", 3)}, nil)
	if len(plan.Create) != 3 {
		t.Fatalf("asked for %d claims, want 3", len(plan.Create))
	}
	if len(plan.Remove) != 0 {
		t.Errorf("released %d claims with none held", len(plan.Remove))
	}
	for _, c := range plan.Create {
		if c.Name != ClaimName("cs301-lab") {
			t.Errorf("claim name %q, want %q", c.Name, ClaimName("cs301-lab"))
		}
		if c.Owner != "ada@example.org" || c.Project != "cs301" {
			t.Errorf("claim carries owner %q project %q", c.Owner, c.Project)
		}
	}
}

// Seats is the whole answer: unlike the machine-attribute path there is
// nothing to subtract for jobs already running, because a claim running
// a job is still the same claim.
func TestPlanClaimsDoesNotSubtractRunningJobs(t *testing.T) {
	spec := claimSpec("cs301-lab", 2)
	held := []Claim{
		{ID: 10, Name: ClaimName("cs301-lab")},
		{ID: 11, Name: ClaimName("cs301-lab")},
	}
	plan := PlanClaims([]*Spec{spec}, held)
	if !plan.Empty() {
		t.Fatalf("plan changed something when the claims already match: %+v", plan)
	}
}

// Shrinking gives up the newest claims. The oldest are likeliest to
// have settled onto a machine, and a claim given back has to be
// re-acquired by waiting.
func TestPlanClaimsShrinksFromTheNewest(t *testing.T) {
	spec := claimSpec("cs301-lab", 1)
	held := []Claim{
		{ID: 10, Name: ClaimName("cs301-lab")},
		{ID: 31, Name: ClaimName("cs301-lab")},
		{ID: 22, Name: ClaimName("cs301-lab")},
	}
	plan := PlanClaims([]*Spec{spec}, held)
	if got := claimIDs(plan); len(got) != 2 || got[0] != 22 || got[1] != 31 {
		t.Fatalf("released %v, want the two newest (22 and 31)", got)
	}
	if len(plan.Create) != 0 {
		t.Errorf("asked for %d more claims while shrinking", len(plan.Create))
	}
}

// A reservation that is gone, disabled, or no longer always-on gets its
// claims back. This is how capacity is returned, and nothing else does
// it: the schedd never gives a persistent claim up on its own.
func TestPlanClaimsReleasesWhatNobodyIsAskingFor(t *testing.T) {
	held := []Claim{
		{ID: 1, Name: ClaimName("deleted")},
		{ID: 2, Name: ClaimName("disabled")},
		{ID: 3, Name: ClaimName("now-scheduled")},
	}
	disabled := claimSpec("disabled", 2)
	disabled.Enabled = false
	scheduled := claimSpec("now-scheduled", 2)
	scheduled.Kind = KindCron
	scheduled.Schedule = mustSchedule(t, "0 9 * * 1", time.UTC)
	scheduled.Duration = time.Hour
	scheduled.Lead = time.Hour

	plan := PlanClaims([]*Spec{disabled, scheduled}, held)
	if got := claimIDs(plan); len(got) != 3 {
		t.Fatalf("released %v, want all three", got)
	}
	if len(plan.Create) != 0 {
		t.Errorf("asked for %d claims for reservations that are not asking", len(plan.Create))
	}
}

// Claims this subsystem did not create are left alone, whatever they
// are for. The query returns every claim on the schedd, so the prefix
// is the only thing separating ours from somebody else's -- and
// removing somebody else's would take capacity from a user who never
// touched a reservation.
func TestPlanClaimsLeavesForeignClaimsAlone(t *testing.T) {
	held := []Claim{
		{ID: 1, Name: "OCU-1"},
		{ID: 2, Name: "someone-elses"},
		{ID: 3, Name: ""},
		{ID: 4, Name: "reservation"}, // the prefix without its colon
	}
	plan := PlanClaims(nil, held)
	if len(plan.Remove) != 0 {
		t.Fatalf("released %v, which this subsystem did not create", plan.Remove)
	}
}

// A submit file that will not render produces no claims and says why.
// An unshaped claim would match any machine at all, which is worse than
// holding nothing.
func TestPlanClaimsRefusesAnUnshapedReservation(t *testing.T) {
	spec := claimSpec("broken", 2)
	spec.Submit = "this is not a submit file"
	plan := PlanClaims([]*Spec{spec}, nil)
	if len(plan.Create) != 0 {
		t.Fatalf("asked for %d claims with no shape to claim", len(plan.Create))
	}
	if plan.Shapes["broken"] == nil {
		t.Fatal("the plan does not say why the reservation got no claims")
	}
}

// The shape sent is the machine request, not the job. Sending the whole
// rendered ad would put a copy of the submit file in the schedd's user
// record once per claim.
func TestPlanClaimsSendsTheRequestNotTheJob(t *testing.T) {
	plan := PlanClaims([]*Spec{claimSpec("cs301-lab", 1)}, nil)
	if len(plan.Create) != 1 {
		t.Fatalf("asked for %d claims, want 1", len(plan.Create))
	}
	ad := plan.Create[0].Request
	if v, ok := ad.EvaluateAttrInt("RequestCpus"); !ok || v != 2 {
		t.Errorf("RequestCpus = %v (present %v), want 2", v, ok)
	}
	if _, ok := ad.Lookup("Requirements"); !ok {
		t.Error("the claim carries no Requirements, so it would match machines the jobs cannot use")
	}
	if _, ok := ad.Lookup("Cmd"); ok {
		t.Error("the claim carries the executable, which says nothing about which machine fits")
	}
}

// fakeHolder records what it was asked to do, and can refuse.
type fakeHolder struct {
	claims   []Claim
	created  []ClaimRequest
	removed  []int64
	failNext error
}

func (f *fakeHolder) List(context.Context) ([]Claim, error) { return f.claims, nil }
func (f *fakeHolder) Create(_ context.Context, r ClaimRequest) error {
	if f.failNext != nil {
		err := f.failNext
		f.failNext = nil
		return err
	}
	f.created = append(f.created, r)
	return nil
}
func (f *fakeHolder) Remove(_ context.Context, id int64) error {
	f.removed = append(f.removed, id)
	return nil
}

// Releases go before requests, so a pool at its limit can give capacity
// back before more is asked for.
func TestReconcileClaimsReleasesBeforeItAsks(t *testing.T) {
	h := &fakeHolder{}
	plan := ClaimPlan{
		Remove: []int64{7},
		Create: []ClaimRequest{{Name: ClaimName("a"), Owner: "ada@example.org", Reservation: "a"}},
	}
	res := ReconcileClaims(context.Background(), h, plan)
	if res.Removed != 1 || res.Created != 1 {
		t.Fatalf("removed %d created %d, want 1 and 1", res.Removed, res.Created)
	}
	if len(h.removed) != 1 || len(h.created) != 1 {
		t.Fatalf("holder saw %d removes and %d creates", len(h.removed), len(h.created))
	}
}

// One refusal does not stop the rest, and it is reported rather than
// swallowed: a reservation that silently holds nothing is the failure
// this whole subsystem is most prone to.
func TestReconcileClaimsCarriesOnPastOneRefusal(t *testing.T) {
	h := &fakeHolder{failNext: errors.New("not an OCU super user")}
	plan := ClaimPlan{Create: []ClaimRequest{
		{Name: ClaimName("a"), Reservation: "a"},
		{Name: ClaimName("a"), Reservation: "a"},
	}}
	res := ReconcileClaims(context.Background(), h, plan)
	if res.Created != 1 {
		t.Errorf("created %d, want the second one to have gone through", res.Created)
	}
	err := res.Err()
	if err == nil {
		t.Fatal("the refusal was swallowed")
	}
	if got := err.Error(); !strings.Contains(got, "not an OCU super user") {
		t.Errorf("the error does not say what the schedd said: %q", got)
	}
}
