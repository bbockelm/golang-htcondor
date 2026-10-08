package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
)

// --- leads file and pattern ------------------------------------------------

func TestParseProjectLeads(t *testing.T) {
	const file = `
# project   leads
CHTC_Staff  alice, bob %chtc-admins   # trailing comment
cs101       %cs101-tas,carol
cs101       dave                        # a second line for the same project
CS101       erin                        # case-insensitive: same project

lonely
bad"name    mallory
weird       %
`
	entries, warnings, err := parseProjectLeads(strings.NewReader(file))
	if err != nil {
		t.Fatalf("parseProjectLeads: %v", err)
	}

	staff := entries["chtc_staff"]
	if staff == nil {
		t.Fatalf("CHTC_Staff missing; got %v", entries)
	}
	if staff.project != "CHTC_Staff" {
		t.Errorf("project spelling = %q, want the file's", staff.project)
	}
	if want := []string{"alice", "bob"}; !reflect.DeepEqual(staff.users, want) {
		t.Errorf("users = %v, want %v", staff.users, want)
	}
	if want := []string{"chtc-admins"}; !reflect.DeepEqual(staff.groups, want) {
		t.Errorf("groups = %v, want %v", staff.groups, want)
	}

	cs := entries["cs101"]
	if cs == nil {
		t.Fatalf("cs101 missing")
	}
	if want := []string{"carol", "dave", "erin"}; !reflect.DeepEqual(cs.users, want) {
		t.Errorf("cs101 users = %v, want %v (lines merge, case-insensitively)", cs.users, want)
	}
	if want := []string{"cs101-tas"}; !reflect.DeepEqual(cs.groups, want) {
		t.Errorf("cs101 groups = %v, want %v", cs.groups, want)
	}

	if _, ok := entries["lonely"]; ok {
		t.Errorf("a project with no leads should not be an entry")
	}
	for key := range entries {
		if strings.Contains(key, `"`) {
			t.Errorf("a project name with a quote was accepted: %q", key)
		}
	}
	// lonely, bad"name, and the bare %.
	if len(warnings) != 3 {
		t.Errorf("warnings = %v, want 3", warnings)
	}
}

func writeLeadsFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "project-leads")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write leads file: %v", err)
	}
	return path
}

func TestProjectLeadsFromFile(t *testing.T) {
	path := writeLeadsFile(t, "Physics alice %physics-leads\nChem bob\n")
	p := newProjectLeads(path, "", nil)

	for _, tc := range []struct {
		name    string
		user    string
		groups  []string
		project string
		want    bool
	}{
		{"named user", "alice", nil, "Physics", true},
		{"named user, qualified and in another case", "ALICE@example.org", nil, "physics", true},
		{"named user, other project", "alice", nil, "Chem", false},
		{"group member", "zed", []string{"Physics-Leads"}, "Physics", true},
		{"group member, other project", "zed", []string{"physics-leads"}, "Chem", false},
		{"nobody", "mallory", []string{"users"}, "Physics", false},
		{"unknown project", "alice", nil, "Biology", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Leads(tc.project, tc.user, tc.groups); got != tc.want {
				t.Errorf("Leads(%q, %q, %v) = %v, want %v", tc.project, tc.user, tc.groups, got, tc.want)
			}
		})
	}

	if got := p.LedProjects("alice", []string{"chem-x"}); !reflect.DeepEqual(got, []string{"Physics"}) {
		t.Errorf("LedProjects(alice) = %v", got)
	}
	if got := p.LedProjects("mallory", nil); len(got) != 0 {
		t.Errorf("LedProjects(mallory) = %v, want none", got)
	}
}

// TestProjectLeadUserEntryDomain: an entry that names a domain matches only
// that identity, while a bare entry matches the name in any domain.
func TestProjectLeadUserEntryDomain(t *testing.T) {
	p := newProjectLeads(writeLeadsFile(t, "Qualified bob@other.org\nBare bob\n"), "", nil)

	for _, tc := range []struct {
		project, user string
		want          bool
	}{
		{"Qualified", "bob@other.org", true},
		{"Qualified", "BOB@Other.ORG", true},
		{"Qualified", "bob@example.org", false},
		{"Qualified", "bob", false},
		{"Bare", "bob@example.org", true},
		{"Bare", "bob@other.org", true},
		{"Bare", "bob", true},
	} {
		if got := p.Leads(tc.project, tc.user, nil); got != tc.want {
			t.Errorf("Leads(%q, %q) = %v, want %v", tc.project, tc.user, got, tc.want)
		}
	}
	if got := p.LedProjects("bob@example.org", nil); !reflect.DeepEqual(got, []string{"Bare"}) {
		t.Errorf("LedProjects(bob@example.org) = %v, want [Bare]", got)
	}
	if got := p.LedProjects("bob@other.org", nil); !reflect.DeepEqual(got, []string{"Bare", "Qualified"}) {
		t.Errorf("LedProjects(bob@other.org) = %v, want [Bare Qualified]", got)
	}
}

// TestProjectLeadsGroupPattern covers HTTP_API_PROJECT_LEADS_GROUP in both
// directions -- "is this caller a lead of P" and "which projects does this
// caller lead" -- and that the two agree.
func TestProjectLeadsGroupPattern(t *testing.T) {
	p := newProjectLeads("", "{project}-leads", nil)
	groups := []string{"users", "Physics-LEADS", "cs101-leads", "-leads", "leads"}

	got := p.LedProjects("anyone", groups)
	if want := []string{"cs101", "Physics"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("LedProjects = %v, want %v", got, want)
	}
	for _, project := range got {
		if !p.Leads(project, "anyone", groups) {
			t.Errorf("LedProjects says %q but Leads disagrees", project)
		}
	}
	if !p.Leads("PHYSICS", "anyone", groups) {
		t.Errorf("project names should compare case-insensitively")
	}
	if p.Leads("users", "anyone", groups) {
		t.Errorf("a group that does not match the pattern granted a project")
	}

	// A prefix pattern works the same way.
	pre := newProjectLeads("", "lead_{project}", nil)
	if got := pre.LedProjects("x", []string{"LEAD_bio", "leadbio"}); !reflect.DeepEqual(got, []string{"bio"}) {
		t.Errorf("prefix pattern: LedProjects = %v, want [bio]", got)
	}
	if !pre.Leads("bio", "x", []string{"lead_BIO"}) {
		t.Errorf("prefix pattern: Leads(bio) = false")
	}

	for _, bad := range []string{"leads", "{project}-{project}"} {
		if newProjectLeads("", bad, nil).configured() {
			t.Errorf("pattern %q should be refused", bad)
		}
	}
}

// TestProjectLeadsFileReloads: the file is the revocation path, so an edit
// must take effect without a restart, and an unreadable file must grant
// nothing rather than keep the last copy.
func TestProjectLeadsFileReloads(t *testing.T) {
	path := writeLeadsFile(t, "Physics alice\n")
	p := newProjectLeads(path, "", nil)
	p.reloadEvery = time.Nanosecond
	if !p.Leads("Physics", "alice", nil) {
		t.Fatalf("alice should lead Physics")
	}

	// A different size, so the change is seen whatever the mtime
	// resolution of the filesystem.
	if err := os.WriteFile(path, []byte("Physics bob, carol\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p.Leads("Physics", "alice", nil) {
		t.Errorf("alice still leads Physics after being removed from the file")
	}
	if !p.Leads("Physics", "carol", nil) {
		t.Errorf("carol was added but does not lead Physics")
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if p.Leads("Physics", "carol", nil) {
		t.Errorf("a missing file still granted leadership")
	}

	// A file that was never there is the same: no leads, and no panic.
	missing := newProjectLeads(filepath.Join(t.TempDir(), "absent"), "", nil)
	if !missing.configured() {
		t.Errorf("a configured path should count as configured even when unreadable")
	}
	if got := missing.LedProjects("alice", nil); len(got) != 0 {
		t.Errorf("missing file granted %v", got)
	}
}

// --- constraint construction ----------------------------------------------

// evalConstraint evaluates a constraint against an ad the way the schedd
// would: only a boolean true matches.
func evalConstraint(t *testing.T, constraint string, ad *classad.ClassAd) bool {
	t.Helper()
	expr, err := classad.ParseExpr(constraint)
	if err != nil {
		t.Fatalf("constraint %q does not parse: %v", constraint, err)
	}
	v := expr.Eval(ad)
	if !v.IsBool() {
		return false
	}
	b, _ := v.BoolValue()
	return b
}

func leadJobAd(cluster int, owner, project string, status int) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttr("ClusterId", int64(cluster))
	ad.InsertAttr("ProcId", 0)
	ad.InsertAttrString("Owner", owner)
	if project != "" {
		ad.InsertAttrString("ProjectName", project)
	}
	ad.InsertAttr("JobStatus", int64(status))
	return ad
}

func TestProjectClauseSemantics(t *testing.T) {
	inPhysics := leadJobAd(1, "bob", "physics", 1) // differs in case from the lead's spelling
	inChem := leadJobAd(2, "bob", "Chem", 1)
	noProject := leadJobAd(3, "bob", "", 1)
	intProject := classad.New()
	intProject.InsertAttr("ProjectName", 7)
	mine := leadJobAd(4, "alice", "Chem", 1)

	clause := projectClause([]string{"Physics"})
	if !evalConstraint(t, clause, inPhysics) {
		t.Errorf("%s should match ProjectName \"physics\" (ClassAd == is case-insensitive)", clause)
	}
	if evalConstraint(t, clause, inChem) || evalConstraint(t, clause, noProject) || evalConstraint(t, clause, intProject) {
		t.Errorf("%s matched a job outside the project", clause)
	}
	// The =?= true wrapper is what keeps an undefined ProjectName from
	// leaking through an enclosing ||.
	if evalConstraint(t, "("+clause+") || (ProjectName == \"nope\")", noProject) {
		t.Errorf("an undefined ProjectName leaked through ||")
	}

	for _, user := range []string{"JobStatus == 1 || true", "true || false", "(JobStatus == 1) || (true)"} {
		scoped, err := scopeToProjects([]string{"Physics"}, user)
		if err != nil {
			t.Fatalf("scopeToProjects(%q): %v", user, err)
		}
		if evalConstraint(t, scoped, inChem) || evalConstraint(t, scoped, noProject) {
			t.Errorf("user constraint %q widened %q", user, scoped)
		}
		if !evalConstraint(t, scoped, inPhysics) {
			t.Errorf("%q should still match the project's job", scoped)
		}

		read, err := scopeToOwnerOrProjects("alice", []string{"Physics"}, user)
		if err != nil {
			t.Fatalf("scopeToOwnerOrProjects(%q): %v", user, err)
		}
		if evalConstraint(t, read, inChem) || evalConstraint(t, read, noProject) {
			t.Errorf("user constraint %q widened the read scope %q", user, read)
		}
		if !evalConstraint(t, read, inPhysics) || !evalConstraint(t, read, mine) {
			t.Errorf("read scope %q should include the project's jobs and the caller's own", read)
		}
	}
	// An unbalanced constraint is refused, not spliced.
	if _, err := scopeToProjects([]string{"Physics"}, "true) || (true"); err == nil {
		t.Errorf("an unbalanced constraint was accepted")
	}
	if _, err := scopeToOwnerOrProjects("alice", []string{"Physics"}, "true) || (true"); err == nil {
		t.Errorf("an unbalanced constraint was accepted for the read scope")
	}
	if got := projectClause(nil); got != "false" {
		t.Errorf("no projects should match nothing, got %q", got)
	}
}

// --- superuser mode, project scope ----------------------------------------

// leadTestEnv is a handler with superuser mode on, a session store, and the
// schedd replaced by in-memory job ads that constraints are really evaluated
// against.
type leadTestEnv struct {
	t         *testing.T
	h         *Handler
	leadsPath string

	mu          sync.Mutex
	ads         []*classad.ClassAd
	constraints []string
}

func newLeadTestEnv(t *testing.T, superuserGroup, leadsFile, leadsPattern string) *leadTestEnv {
	t.Helper()
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	env := &leadTestEnv{t: t}
	if leadsFile != "" {
		env.leadsPath = writeLeadsFile(t, leadsFile)
	}
	h := &Handler{
		logger:         logger,
		uidDomain:      "example.org",
		trustDomain:    "example.org",
		signingKeyPath: writeSigningKey(t),
		sessionStore:   createTestSessionStore(t, time.Hour),
		tokenCache:     NewTokenCache(),
	}
	h.initSuperuserMode(HandlerConfig{
		SuperuserGroup:    superuserGroup,
		ProjectLeadsFile:  env.leadsPath,
		ProjectLeadsGroup: leadsPattern,
	}, logger)
	if !h.superuserModeAvailable() {
		t.Fatalf("superuser mode did not enable")
	}
	// Nobody is a queue superuser: leads act via the fallback identity.
	h.superuserPolicy.source = &fakeSuperUsers{users: []string{"condor@example.org"}}
	if err := h.superuserPolicy.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	h.projectLeads.reloadEvery = time.Nanosecond
	h.superuserJobQuery = env.query
	env.h = h
	return env
}

func (e *leadTestEnv) query(_ context.Context, constraint string, _ []string, limit int) ([]*classad.ClassAd, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.constraints = append(e.constraints, constraint)
	var out []*classad.ClassAd
	for _, ad := range e.ads {
		if evalConstraint(e.t, constraint, ad) {
			out = append(out, ad)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (e *leadTestEnv) session(user string, groups ...string) string {
	e.t.Helper()
	sid, _, err := e.h.sessionStore.Create(user, groups)
	if err != nil {
		e.t.Fatalf("session for %s: %v", user, err)
	}
	return sid
}

func (e *leadTestEnv) request(method, target, sid string, body any) *http.Request {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequestWithContext(context.Background(), method, target, &buf)
	r.Header.Set("Content-Type", "application/json")
	if sid != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
	}
	return r
}

// arm arms superuser mode through the endpoint and returns the response.
func (e *leadTestEnv) arm(sid string) (int, SuperuserModeResponse) {
	e.t.Helper()
	w := httptest.NewRecorder()
	e.h.handleSuperuserMode(w, e.request(http.MethodPost, "/api/v1/admin/superuser", sid, map[string]bool{"enabled": true}))
	var resp SuperuserModeResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w.Code, resp
}

// recordedAction is a JobActionFunc that records what it was asked to do and
// which identity it would have done it as, and reports that every job its
// constraint matches was acted on.
type recordedAction struct {
	env   *leadTestEnv
	calls []actionCall
}

type actionCall struct {
	constraint string
	reason     string
	identity   string
	matched    []int64
}

func (a *recordedAction) fn(ctx context.Context, constraint, reason string) (*htcondor.JobActionResults, error) {
	call := actionCall{constraint: constraint, reason: reason}
	if cfg, ok := htcondor.GetSecurityConfigFromContext(ctx); ok {
		call.identity = cfg.SecurityTag
	}
	for _, ad := range a.env.ads {
		if evalConstraint(a.env.t, constraint, ad) {
			id, _ := ad.EvaluateAttrInt("ClusterId")
			call.matched = append(call.matched, id)
		}
	}
	a.calls = append(a.calls, call)
	n := len(call.matched)
	return &htcondor.JobActionResults{TotalJobs: n, Success: n}, nil
}

func (a *recordedAction) actedOn() []int64 {
	var out []int64
	for _, c := range a.calls {
		out = append(out, c.matched...)
	}
	slices.Sort(out)
	return out
}

// TestProjectLeadArmsWithoutSuperuserGroup: project leads must work with
// HTTP_API_SUPERUSER_GROUP unset -- and an unset group must not make
// everybody a global superuser, which is what groupSet.allows would say about
// an empty list.
func TestProjectLeadArmsWithoutSuperuserGroup(t *testing.T) {
	env := newLeadTestEnv(t, "", "Physics alice\n", "")

	code, resp := env.arm(env.session("alice", "users"))
	if code != http.StatusOK {
		t.Fatalf("lead could not arm: %d", code)
	}
	if !resp.Active || resp.Scope != "project" || !reflect.DeepEqual(resp.Projects, []string{"Physics"}) {
		t.Errorf("arm response = %+v, want project scope for [Physics]", resp)
	}

	code, _ = env.arm(env.session("mallory", "users"))
	if code != http.StatusForbidden {
		t.Errorf("a non-lead armed superuser mode: %d", code)
	}
	if env.h.globalSuperuser([]string{"users"}) {
		t.Errorf("an empty HTTP_API_SUPERUSER_GROUP made a session a global superuser")
	}

	// The group pattern alone is enough too.
	byGroup := newLeadTestEnv(t, "", "", "{project}-leads")
	code, resp = byGroup.arm(byGroup.session("zed", "users", "CS101-leads"))
	if code != http.StatusOK || resp.Scope != "project" || !reflect.DeepEqual(resp.Projects, []string{"CS101"}) {
		t.Errorf("pattern lead arm = %d %+v, want project scope for [CS101]", code, resp)
	}
	if code, _ := byGroup.arm(byGroup.session("mallory", "users")); code != http.StatusForbidden {
		t.Errorf("a session in no lead group armed: %d", code)
	}
}

// TestProjectLeadAuthMeReportsScope covers what the banner reads.
func TestProjectLeadAuthMeReportsScope(t *testing.T) {
	env := newLeadTestEnv(t, "admins", "Physics alice\nChem alice\n", "")
	sid := env.session("alice")
	if code, _ := env.arm(sid); code != http.StatusOK {
		t.Fatalf("arm: %d", code)
	}
	w := httptest.NewRecorder()
	env.h.handleAuthMe(w, env.request(http.MethodGet, "/api/v1/auth/me", sid, nil))
	var me AuthMeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if !me.SuperuserActive || me.SuperuserScope != "project" ||
		!reflect.DeepEqual(me.SuperuserProjects, []string{"Chem", "Physics"}) {
		t.Errorf("auth/me = %+v, want active project scope for [Chem Physics]", me)
	}
	if !reflect.DeepEqual(me.ProjectLeadOf, []string{"Chem", "Physics"}) {
		t.Errorf("project_lead_of = %v", me.ProjectLeadOf)
	}

	admin := env.session("root", "admins")
	if code, resp := env.arm(admin); code != http.StatusOK || resp.Scope != "global" {
		t.Errorf("global arm = %d %+v, want global scope", code, resp)
	}
}

func holdOne(env *leadTestEnv, sid, jobID string) (*httptest.ResponseRecorder, *recordedAction) {
	act := &recordedAction{env: env}
	w := httptest.NewRecorder()
	env.h.handleSingleJobAction(w, env.request(http.MethodPost, "/api/v1/jobs/"+jobID+"/hold", sid,
		map[string]string{"reason": "caller text"}), jobID, "Held", "hold", act.fn)
	return w, act
}

// TestProjectLeadSingleJobAction is the core rule: a lead acts on another
// user's job only when the job is in a project they lead.
func TestProjectLeadSingleJobAction(t *testing.T) {
	env := newLeadTestEnv(t, "", "Physics alice\n", "")
	env.ads = []*classad.ClassAd{
		leadJobAd(1, "bob", "physics", 1), // led, different case
		leadJobAd(2, "bob", "Chem", 1),    // another project
		leadJobAd(3, "bob", "", 1),        // no project at all
		leadJobAd(4, "alice", "Chem", 1),  // the lead's own job
	}
	sid := env.session("alice")
	if code, _ := env.arm(sid); code != http.StatusOK {
		t.Fatalf("arm: %d", code)
	}

	t.Run("led project is acted on as the fallback identity", func(t *testing.T) {
		w, act := holdOne(env, sid, "1.0")
		if len(act.calls) != 1 {
			t.Fatalf("action not performed: %d %s", w.Code, w.Body.String())
		}
		call := act.calls[0]
		if !reflect.DeepEqual(call.matched, []int64{1}) {
			t.Errorf("acted on %v, want [1]", call.matched)
		}
		if !strings.Contains(call.constraint, "ProjectName") {
			t.Errorf("constraint %q does not carry the project clause the schedd re-checks", call.constraint)
		}
		if want := "Held by alice@example.org via the web UI (project lead for Physics, acting for bob@example.org)"; call.reason != want {
			t.Errorf("reason = %q, want %q", call.reason, want)
		}
		if !strings.Contains(call.identity, "condor@example.org->bob@example.org") {
			t.Errorf("acted as %q, want the fallback identity for bob", call.identity)
		}
	})

	for _, tc := range []struct{ name, job string }{
		{"another project is refused", "2.0"},
		{"no ProjectName is refused", "3.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, act := holdOne(env, sid, tc.job)
			if w.Code != http.StatusForbidden {
				t.Errorf("status = %d, want 403 (%s)", w.Code, w.Body.String())
			}
			if len(act.calls) != 0 {
				t.Errorf("the action ran anyway: %+v", act.calls)
			}
			if !strings.Contains(w.Body.String(), "project you lead") {
				t.Errorf("refusal does not say why: %s", w.Body.String())
			}
		})
	}

	t.Run("the TOCTOU clause holds if the owner moves the job", func(t *testing.T) {
		moved := leadJobAd(1, "bob", "Chem", 1)
		imp := &Impersonation{Target: "bob@example.org", Project: "Physics"}
		constraint, err := env.h.scopeForImpersonation(imp, 1, 0)
		if err != nil {
			t.Fatal(err)
		}
		if evalConstraint(t, constraint, moved) {
			t.Errorf("%q still matches a job moved out of the project", constraint)
		}
		if !evalConstraint(t, constraint, env.ads[0]) {
			t.Errorf("%q does not match the job in the project", constraint)
		}
	})

	t.Run("own job is not an impersonation", func(t *testing.T) {
		_, act := holdOne(env, sid, "4.0")
		if len(act.calls) != 1 {
			t.Fatalf("own-job action not performed")
		}
		if act.calls[0].reason != "caller text" {
			t.Errorf("own job got reason %q, want the caller's", act.calls[0].reason)
		}
	})
}

// TestGlobalSuperuserUnchangedByProjects: a global superuser still reaches
// jobs in any project, or none, with the original reason text.
func TestGlobalSuperuserUnchangedByProjects(t *testing.T) {
	env := newLeadTestEnv(t, "admins", "Physics alice\n", "")
	env.ads = []*classad.ClassAd{leadJobAd(3, "bob", "", 1)}
	sid := env.session("root", "admins")
	if code, _ := env.arm(sid); code != http.StatusOK {
		t.Fatalf("arm: %d", code)
	}
	_, act := holdOne(env, sid, "3.0")
	if len(act.calls) != 1 {
		t.Fatalf("global superuser was refused a job with no project")
	}
	if want := "Held by root@example.org via the web UI (superuser mode, acting for bob@example.org)"; act.calls[0].reason != want {
		t.Errorf("reason = %q, want %q", act.calls[0].reason, want)
	}
	if strings.Contains(act.calls[0].constraint, "ProjectName") {
		t.Errorf("global scope should not add a project clause: %q", act.calls[0].constraint)
	}
}

// TestProjectLeadRevokedAfterArming: leadership is re-read on every action,
// so editing the file takes effect before the arm expires.
func TestProjectLeadRevokedAfterArming(t *testing.T) {
	env := newLeadTestEnv(t, "", "Physics alice\n", "")
	env.ads = []*classad.ClassAd{leadJobAd(1, "bob", "Physics", 1)}
	sid := env.session("alice")
	if code, _ := env.arm(sid); code != http.StatusOK {
		t.Fatalf("arm: %d", code)
	}
	if err := os.WriteFile(env.leadsPath, []byte("Physics carol, dave\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	w, act := holdOne(env, sid, "1.0")
	if w.Code != http.StatusForbidden || len(act.calls) != 0 {
		t.Fatalf("revoked lead still acted: %d %+v", w.Code, act.calls)
	}
	if _, armed := env.h.superuserArmed.Armed(sid); armed {
		t.Errorf("the revoked session was left armed")
	}
}

// TestProjectLeadArmCapsScope: a session armed as a lead does not become
// global because its user was added to the superuser group afterwards, and a
// session armed globally falls back to its projects if the group is lost.
func TestProjectLeadArmCapsScope(t *testing.T) {
	env := newLeadTestEnv(t, "admins", "Physics alice\n", "")
	both := &SessionData{Username: "alice", Groups: []string{"admins"}}
	leadOnly := &SessionData{Username: "alice"}

	if eff := effectiveSuperuserScope(armedSession{projectScoped: true}, env.h.superuserScopeFor(both)); eff.Global {
		t.Errorf("a project-armed session became global")
	}
	eff := effectiveSuperuserScope(armedSession{}, env.h.superuserScopeFor(leadOnly))
	if eff.Global || !reflect.DeepEqual(eff.Projects, []string{"Physics"}) {
		t.Errorf("a globally armed session that lost the group = %+v, want project scope", eff)
	}
	if eff := effectiveSuperuserScope(armedSession{}, env.h.superuserScopeFor(both)); !eff.Global {
		t.Errorf("a globally armed superuser lost global scope")
	}
}

// TestProjectLeadBulkCannotWiden: a lead's bulk action reaches their own jobs
// and their projects' jobs, and a constraint ending "|| true" does not reach
// anything else.
func TestProjectLeadBulkCannotWiden(t *testing.T) {
	env := newLeadTestEnv(t, "", "Physics alice\n", "")
	env.ads = []*classad.ClassAd{
		leadJobAd(1, "bob", "Physics", 1),
		leadJobAd(2, "carol", "physics", 1),
		leadJobAd(3, "bob", "Chem", 1),
		leadJobAd(4, "bob", "", 1),
		leadJobAd(5, "alice", "Chem", 1),
		leadJobAd(6, "dave", "Chem", 1),
	}
	sid := env.session("alice")
	if code, _ := env.arm(sid); code != http.StatusOK {
		t.Fatalf("arm: %d", code)
	}

	for _, user := range []string{"JobStatus == 1 || true", "true"} {
		t.Run(user, func(t *testing.T) {
			env.constraints = nil
			act := &recordedAction{env: env}
			w := httptest.NewRecorder()
			env.h.handleBulkJobAction(w, env.request(http.MethodPost, "/api/v1/jobs/hold", sid,
				map[string]string{"constraint": user}), "Held", "hold", act.fn)
			if w.Code != http.StatusOK {
				t.Fatalf("bulk hold = %d: %s", w.Code, w.Body.String())
			}
			if got, want := act.actedOn(), []int64{1, 2, 5}; !reflect.DeepEqual(got, want) {
				t.Errorf("acted on %v, want %v (own job plus Physics)", got, want)
			}
			// The planning read itself was confined, not just the
			// batches: jobs outside the scope are never read.
			if len(env.constraints) == 0 || !strings.HasPrefix(env.constraints[0], "((Owner == \"alice\") || ") {
				t.Errorf("the planning query was not scoped first: %v", env.constraints)
			}
			for _, c := range act.calls {
				if strings.Contains(c.reason, "acting for") && !strings.Contains(c.reason, "project lead for Physics") {
					t.Errorf("batch reason does not name the project: %q", c.reason)
				}
			}
		})
	}
}

// TestJobProxyRefusesProjectLead: the browser-proxied app path is the one
// remote-access route project leads do not get, while a global superuser
// keeps it.
func TestJobProxyRefusesProjectLead(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "hello from the job")
	}))
	defer backend.Close()

	h := newProxyTestHandler(t, strings.TrimPrefix(backend.URL, "http://"))
	h.userHeader = ""
	h.userHeaderUnsafeAllowAll = false
	h.sessionStore = createTestSessionStore(t, time.Hour)
	h.initSuperuserMode(HandlerConfig{
		SuperuserGroup:   "admins",
		ProjectLeadsFile: writeLeadsFile(t, "Physics alice\n"),
	}, h.logger)
	h.superuserPolicy.source = &fakeSuperUsers{users: []string{"condor@test.htcondor.org"}}
	_ = h.superuserPolicy.Refresh(context.Background())
	ad := leadJobAd(12, "bob", "Physics", 2)
	h.superuserJobQuery = func(context.Context, string, []string, int) ([]*classad.ClassAd, error) {
		return []*classad.ClassAd{ad}, nil
	}

	proxy := func(user string, groups ...string) *httptest.ResponseRecorder {
		sid, _, err := h.sessionStore.Create(user, groups)
		if err != nil {
			t.Fatal(err)
		}
		armed := h.resolveImpersonationIdentity(context.Background(), user)
		armed.projectScoped = !h.globalSuperuser(groups)
		h.superuserArmed.Arm(sid, armed)
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/jobs/12.0/proxy/8080/", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid}) //nolint:gosec
		w := httptest.NewRecorder()
		h.handleJobProxy(w, r, 12, 0, jobProxyTarget{Port: 8080}, "/")
		return w
	}

	if w := proxy("alice"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "interactive app") {
		t.Errorf("project lead reached bob's app: %d %s", w.Code, w.Body.String())
	}
	if w := proxy("root", "admins"); w.Code != http.StatusOK {
		t.Errorf("global superuser was refused the proxy: %d %s", w.Code, w.Body.String())
	}
}

// TestProjectLeadReadScope: a lead reading "everyone" sees their own jobs
// and their projects' jobs, and an admin or non-lead is unaffected.
func TestProjectLeadReadScope(t *testing.T) {
	env := newLeadTestEnv(t, "", "Physics alice\n", "")
	env.h.webuiAdminGroups = newGroupSet("web-admins")
	ads := map[string]*classad.ClassAd{
		"own":     leadJobAd(1, "alice", "Chem", 1),
		"project": leadJobAd(2, "bob", "physics", 1),
		"other":   leadJobAd(3, "bob", "Chem", 1),
		"none":    leadJobAd(4, "bob", "", 1),
	}

	read := func(sid string, cluster int) string {
		r := env.request(http.MethodGet, "/api/v1/jobs", sid, nil)
		ctx := htcondor.WithAuthenticatedUser(context.Background(), env.h.sessionStore.Get(sid).Username)
		c, err := env.h.jobReadScope(ctx, r, cluster, 0)
		if err != nil {
			t.Fatalf("jobReadScope: %v", err)
		}
		return c
	}

	lead := env.session("alice")
	if got := env.h.projectLeadReadProjects(env.request(http.MethodGet, "/", lead, nil)); !reflect.DeepEqual(got, []string{"Physics"}) {
		t.Fatalf("projectLeadReadProjects = %v", got)
	}
	for name, want := range map[string]bool{"own": true, "project": true, "other": false, "none": false} {
		ad := ads[name]
		cluster, _ := ad.EvaluateAttrInt("ClusterId")
		if got := evalConstraint(t, read(lead, int(cluster)), ad); got != want {
			t.Errorf("lead reading %s job: visible = %v, want %v", name, got, want)
		}
	}

	nonLead := env.session("mallory")
	if got := env.h.projectLeadReadProjects(env.request(http.MethodGet, "/", nonLead, nil)); got != nil {
		t.Errorf("non-lead got read projects %v", got)
	}
	if evalConstraint(t, read(nonLead, 2), ads["project"]) {
		t.Errorf("a non-lead could read a project job")
	}

	admin := env.session("alice", "web-admins")
	if got := env.h.projectLeadReadProjects(env.request(http.MethodGet, "/", admin, nil)); got != nil {
		t.Errorf("an admin should not be narrowed to projects, got %v", got)
	}
}

// TestReconfigureOnServerWithoutSuperuserMode: the reconfigure setters run
// against a daemon that started with the mode off. They must not panic, and
// must not switch the mode on (it is built at startup).
func TestReconfigureOnServerWithoutSuperuserMode(t *testing.T) {
	logger, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	h := &Handler{logger: logger, uidDomain: "example.org"}
	h.initSuperuserMode(HandlerConfig{}, logger)

	h.SetSuperuserGroups("admins")
	h.SetProjectLeadsFile(writeLeadsFile(t, "Physics alice\n"))
	h.SetProjectLeadsGroup("{project}-leads")

	if h.superuserModeAvailable() {
		t.Errorf("a reconfigure switched superuser mode on")
	}
	// Read visibility needs no signing key, so it does follow the file.
	if got := h.projectLeads.LedProjects("alice", nil); !reflect.DeepEqual(got, []string{"Physics"}) {
		t.Errorf("leads after reconfigure = %v", got)
	}
}
