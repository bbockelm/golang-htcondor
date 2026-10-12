package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/httpserver/chat"
)

// The chat's job scope.
//
// A page with a Mine/Everyone toggle sends the toggle's position as
// chat.Request.Scope. That is only a request: resolveChatScope settles it
// once per chat request with the same checks the page's own REST endpoint
// makes, and the result is the only thing the engine (system prompt,
// auto-approve) and the tools (chatJobScope) read. A forged "everyone"
// from a caller the page would confine is confined here too.

// chatEveryoneView is what "everyone" can mean on one page.
type chatEveryoneView struct {
	// leads: the page's REST endpoint gives a project lead their own jobs
	// plus their projects' (GET /api/v1/jobs, a job by id, utilization).
	// Without it a lead asking for everyone's gets their own, as the
	// archive and issues endpoints do.
	leads bool
}

// chatEveryonePages are the pages that offer an everyone view, keyed by
// the page identifier the SPA sends. A page missing here (submit, pool)
// always resolves to the caller's own jobs.
//
// The two detail pages have no toggle: they ask for everyone when the job
// they show is someone else's, so the tools reach the job the page has
// already been allowed to read.
var chatEveryonePages = map[string]chatEveryoneView{
	"jobs":           {leads: true},
	"job-detail":     {leads: true},
	"utilization":    {leads: true},
	"archive":        {},
	"archive-detail": {},
	"issues":         {},
}

// resolveChatScope turns the scope a page asked for into the scope the
// caller gets, by the rules of the page's own REST endpoint:
//
//   - everyone's jobs for a caller seesAllJobs grants the read tier;
//     acting on them, too, when it also grants the mutate tier;
//   - on a page whose endpoint offers it, a project lead's own jobs plus
//     those of the projects they lead (projectLeadReadProjects);
//   - otherwise their own jobs.
//
// Multi-AP mode does not offer the chat (handleChatInfo), and there
// seesAllJobs is decided per routed access point, which a chat request
// does not have; it resolves to the caller's own jobs.
func (s *Handler) resolveChatScope(ctx context.Context, r *http.Request, page, requested string) chat.Scope {
	sc := chat.Mine(requested)
	if sc.Requested != chat.ScopeEveryone || s.multi != nil || r == nil {
		return sc
	}
	view, ok := chatEveryonePages[page]
	if !ok {
		return sc
	}
	if s.seesAllJobs(ctx, r, jobScopeRead) {
		sc.Effective = chat.ScopeEveryone
		sc.ActOnOthers = s.seesAllJobs(ctx, r, jobScopeMutate)
		return sc
	}
	if view.leads {
		if projects := s.projectLeadReadProjects(r); len(projects) > 0 {
			sc.Effective = chat.ScopeProjects
			sc.Projects = projects
		}
	}
	return sc
}

// chatJobScope confines an untrusted constraint (the model's) to the jobs
// the chat's resolved scope lets the caller read (jobScopeRead) or act on
// (jobScopeMutate). Every chat tool that reads or changes jobs scopes its
// constraint here.
//
// The constraint is re-serialized before it is ANDed in (andScope), so it
// can only narrow the scope, and one that will not parse is refused. An
// unconfined scope still goes through andScope for that reason.
func chatJobScope(ctx context.Context, actor, constraint string, tier jobScopeTier) (string, error) {
	sc := chat.ScopeFrom(ctx)
	if sc.Effective == chat.ScopeEveryone && (tier == jobScopeRead || sc.ActOnOthers) {
		return andScope("true", constraint)
	}
	owner := ownerFromActor(actor)
	if owner == "" {
		return "", errUnidentifiedCaller
	}
	if sc.Effective == chat.ScopeProjects && tier == jobScopeRead {
		return scopeToOwnerOrProjects(owner, sc.Projects, constraint)
	}
	return scopeToOwner(owner, constraint)
}

// chatScopeLabel says, for a tool result, which jobs a tool covered.
func chatScopeLabel(ctx context.Context, tier jobScopeTier) string {
	sc := chat.ScopeFrom(ctx)
	switch {
	case sc.Effective == chat.ScopeEveryone && (tier == jobScopeRead || sc.ActOnOthers):
		return "every user's jobs"
	case sc.Effective == chat.ScopeProjects && tier == jobScopeRead:
		return "your own jobs and those of the projects you lead (" + strings.Join(sc.Projects, ", ") + ")"
	case sc.Effective != chat.ScopeMine:
		return "your own jobs (you can read other users' jobs here but not act on them)"
	case sc.Denied():
		return "your own jobs (the page asked for everyone's; your own are all you can see)"
	}
	return "your own jobs"
}

// chatTargetJob finds the one job a single-job chat tool would act on,
// within the caller's mutate scope, and returns its Owner. A job outside
// the scope is reported as not found, the same as one that does not exist.
func (s *Handler) chatTargetJob(ctx context.Context, actor string, cluster, proc int) (string, error) {
	owner, _, err := s.chatTargetJobAd(ctx, actor, cluster, proc)
	return owner, err
}

// chatTargetJobAd is chatTargetJob also returning the integer attributes
// named in projection, for a tool that needs more of the ad (run_in_job
// reads JobStatus).
func (s *Handler) chatTargetJobAd(ctx context.Context, actor string, cluster, proc int, projection ...string) (string, map[string]int, error) {
	schedd := s.getSchedd()
	if schedd == nil {
		return "", nil, errors.New("schedd not configured")
	}
	constraint, err := chatJobScope(ctx, actor, fmt.Sprintf("ClusterId == %d && ProcId == %d", cluster, proc), jobScopeMutate)
	if err != nil {
		return "", nil, err
	}
	ads, _, err := schedd.QueryWithOptions(ctx, constraint, &htcondor.QueryOptions{
		Limit:      1,
		Projection: append([]string{"ClusterId", "ProcId", "Owner"}, projection...),
	})
	if err != nil {
		return "", nil, fmt.Errorf("ownership check: %w", err)
	}
	if len(ads) == 0 {
		return "", nil, errChatJobNotFound(cluster, proc)
	}
	owner, _ := readString(ads[0], "Owner")
	if owner == "" {
		return "", nil, fmt.Errorf("job %d.%d has no Owner", cluster, proc)
	}
	ints := map[string]int{}
	for _, name := range projection {
		if v, ok := readInt(ads[0], name); ok {
			ints[name] = v
		}
	}
	return owner, ints, nil
}

func errChatJobNotFound(cluster, proc int) error {
	return fmt.Errorf("job %d.%d either does not exist or is not one you can act on", cluster, proc)
}

// pinnedJobConstraint names one job AND the owner it was found to have, so
// the action matches nothing if the job is somehow not that owner's by the
// time the schedd acts.
func pinnedJobConstraint(cluster, proc int, owner string) string {
	return fmt.Sprintf("ClusterId == %d && ProcId == %d && Owner == %s", cluster, proc, classadStringLit(owner))
}

// describeJobOwner is the approval-card detail for a single-job action:
// the job's owner, when the action may reach other users' jobs and the
// job is not the caller's. When the owner cannot be read the card says
// so rather than staying silent.
func (s *Handler) describeJobOwner(ctx context.Context, actor string, cluster, proc int) map[string]any {
	if !chat.ScopeFrom(ctx).ActOnOthers {
		// The action is confined to the caller's own jobs.
		return nil
	}
	owner, err := s.chatTargetJob(ctx, actor, cluster, proc)
	if err != nil {
		return map[string]any{"owner_unknown": true}
	}
	if strings.EqualFold(owner, ownerFromActor(actor)) {
		return nil
	}
	return map[string]any{"owners": []string{owner}}
}

// chatDescribeOwnersMax caps how many owners a bulk approval card lists.
const chatDescribeOwnersMax = 10

// describeConstraintOwners is the approval-card detail for a bulk action:
// whose jobs the constraint matches, when that can include other users'.
func (s *Handler) describeConstraintOwners(ctx context.Context, actor, constraint string) map[string]any {
	if !chat.ScopeFrom(ctx).ActOnOthers {
		return nil
	}
	schedd := s.getSchedd()
	if schedd == nil {
		return map[string]any{"owner_unknown": true}
	}
	scoped, err := chatJobScope(ctx, actor, constraint, jobScopeMutate)
	if err != nil {
		return map[string]any{"owner_unknown": true}
	}
	ads, _, err := schedd.QueryWithOptions(ctx, scoped, &htcondor.QueryOptions{
		Limit:      removeJobsMaxAffected + 1,
		Projection: []string{"ClusterId", "ProcId", "Owner"},
	})
	if err != nil {
		return map[string]any{"owner_unknown": true}
	}
	counts := map[string]int{}
	for _, ad := range ads {
		owner, _ := readString(ad, "Owner")
		counts[owner]++
	}
	self := ownerFromActor(actor)
	others := false
	names := make([]string, 0, len(counts))
	for owner := range counts {
		if !strings.EqualFold(owner, self) {
			others = true
		}
		names = append(names, owner)
	}
	if !others {
		return nil
	}
	// Most jobs first, then by name, so the card is stable.
	slices.SortFunc(names, func(a, b string) int {
		if counts[a] != counts[b] {
			return counts[b] - counts[a]
		}
		return strings.Compare(a, b)
	})
	listed := make([]string, 0, min(len(names), chatDescribeOwnersMax))
	for _, owner := range names[:min(len(names), chatDescribeOwnersMax)] {
		label := owner
		if owner == "" {
			label = "(no owner)"
		}
		listed = append(listed, fmt.Sprintf("%s (%d)", label, counts[owner]))
	}
	out := map[string]any{"owners": listed}
	if len(names) > chatDescribeOwnersMax {
		out["more_owners"] = len(names) - chatDescribeOwnersMax
	}
	return out
}

// handleChatScope is GET /api/v1/chat/scope?page=<page>&scope=<mine|everyone>:
// the scope the chat would resolve for this caller on that page, so the
// panel can say which jobs the assistant sees before the first message.
// The same resolveChatScope runs on every chat request.
func (s *Handler) handleChatScope(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}
	q := r.URL.Query()
	s.writeJSON(w, http.StatusOK, s.resolveChatScope(ctx, r, q.Get("page"), q.Get("scope")))
}
