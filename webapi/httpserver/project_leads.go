package httpserver

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Project leads: superuser mode confined to one project's jobs.
//
// A "project" is the job ad's ProjectName attribute. A lead of project P may
// arm superuser mode and, while it is armed, act on other users' jobs whose
// ProjectName is P -- and on no others. Leads come from two places, either or
// both of which may be configured:
//
//   - HTTP_API_PROJECT_LEADS_FILE, one project per line:
//     "<project> <lead>[ <lead>...]", leads separated by whitespace or commas,
//     a "%" prefix marking a group (sudoers' convention);
//   - HTTP_API_PROJECT_LEADS_GROUP, a group-name pattern containing
//     "{project}", so that members of "<P>-leads" lead project P.
//
// Group membership is the session's, from HTTP_API_GROUP_SOURCE, compared
// case-insensitively as every other authorization group is (see groupSet).

// projectPlaceholder is the token HTTP_API_PROJECT_LEADS_GROUP must contain.
const projectPlaceholder = "{project}"

// projectLeadsReloadInterval bounds how often the leads file is stat'ed for
// changes. Short, because the file is the revocation path: removing a lead
// should take effect on their next action rather than when their 30-minute
// arm runs out. A stat is cheap enough that this costs nothing worth
// measuring at the rate superuser actions happen.
const projectLeadsReloadInterval = 5 * time.Second

// projectLeadEntry is one project's leads as configured in the file.
type projectLeadEntry struct {
	// project is the name as written in the file. Matching is
	// case-insensitive; this spelling is what goes into constraints and
	// messages.
	project string
	users   []string
	groups  []string
}

// projectLeads holds both lead sources and answers the two questions
// superuser mode asks of them. Safe for concurrent use: a reconfigure
// replaces the path and pattern while requests are reading.
type projectLeads struct {
	logger *logging.Logger
	// reloadEvery overrides projectLeadsReloadInterval; tests shorten it.
	reloadEvery time.Duration

	mu      sync.Mutex
	path    string
	pattern string
	// byProject is keyed by lower-cased project name.
	byProject map[string]*projectLeadEntry
	checkedAt time.Time
	modTime   time.Time
	size      int64
	// lastErr is the most recent load failure, kept so a file that stays
	// broken is logged once rather than on every check.
	lastErr string
}

// newProjectLeads builds the lead sources. A bad pattern or an unreadable
// file is logged and treated as "no leads from that source" rather than
// failing startup: nothing else about the server depends on them, and
// failing closed -- nobody is a lead -- is the safe direction.
func newProjectLeads(path, pattern string, logger *logging.Logger) *projectLeads {
	p := &projectLeads{logger: logger}
	p.SetPattern(pattern)
	p.SetFile(path)
	return p
}

// configured reports whether either source is set. It says nothing about
// whether the file currently names anybody.
func (p *projectLeads) configured() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.path != "" || p.pattern != ""
}

// SetFile installs a leads file path and re-reads it immediately. Called at
// startup and on every reconfigure, whether or not the path changed: the
// usual reason to reconfigure is that the file's contents were edited.
func (p *projectLeads) SetFile(path string) {
	if p == nil {
		return
	}
	path = strings.TrimSpace(path)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.path = path
	p.byProject = nil
	p.checkedAt = time.Time{}
	p.modTime = time.Time{}
	p.size = 0
	p.lastErr = ""
	if path == "" {
		return
	}
	p.reloadLocked(true)
}

// SetPattern installs HTTP_API_PROJECT_LEADS_GROUP. A pattern without
// exactly one "{project}" is refused -- with no placeholder every member of
// that one group would lead every project, and with two the project name
// cannot be recovered from a group name -- and logged, leaving the pattern
// source off.
func (p *projectLeads) SetPattern(pattern string) {
	if p == nil {
		return
	}
	pattern = strings.TrimSpace(pattern)
	if pattern != "" && strings.Count(pattern, projectPlaceholder) != 1 {
		if p.logger != nil {
			p.logger.Error(logging.DestinationSecurity,
				"HTTP_API_PROJECT_LEADS_GROUP must contain \"{project}\" exactly once; ignoring it",
				"pattern", pattern)
		}
		pattern = ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.pattern = pattern
}

// snapshotLocked returns the file's entries, re-reading the file when it has
// changed on disk. Bounded by reloadEvery so a busy page does not stat on
// every request.
func (p *projectLeads) snapshotLocked() map[string]*projectLeadEntry {
	if p.path == "" {
		return nil
	}
	interval := p.reloadEvery
	if interval <= 0 {
		interval = projectLeadsReloadInterval
	}
	if time.Since(p.checkedAt) >= interval {
		p.reloadLocked(false)
	}
	return p.byProject
}

// reloadLocked re-reads the file. Unless force is set, an unchanged file
// (same modification time and size) is not re-parsed.
//
// A file that cannot be read yields NO file-based leads. That is fail-closed
// on purpose: this file grants privilege, and keeping a stale copy when it
// has been made unreadable would keep granting it to whoever the operator
// was in the middle of removing.
func (p *projectLeads) reloadLocked(force bool) {
	p.checkedAt = time.Now()
	info, err := os.Stat(p.path)
	if err == nil && !force && p.byProject != nil &&
		info.ModTime().Equal(p.modTime) && info.Size() == p.size {
		return
	}
	var entries map[string]*projectLeadEntry
	var warnings []string
	if err == nil {
		entries, warnings, err = readProjectLeadsFile(p.path)
	}
	if err != nil {
		p.byProject = nil
		if msg := err.Error(); msg != p.lastErr {
			p.lastErr = msg
			if p.logger != nil {
				p.logger.Error(logging.DestinationSecurity,
					"Could not read HTTP_API_PROJECT_LEADS_FILE; no project leads are defined by it until it can be read",
					"path", p.path, "error", err)
			}
		}
		return
	}
	p.byProject = entries
	p.modTime, p.size = info.ModTime(), info.Size()
	p.lastErr = ""
	if p.logger != nil {
		for _, w := range warnings {
			p.logger.Warn(logging.DestinationSecurity, "HTTP_API_PROJECT_LEADS_FILE: "+w, "path", p.path)
		}
		p.logger.Info(logging.DestinationSecurity, "Loaded project leads",
			"path", p.path, "projects", len(entries))
	}
}

func readProjectLeadsFile(path string) (map[string]*projectLeadEntry, []string, error) {
	fh, err := os.Open(path) //nolint:gosec // the path is operator configuration
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = fh.Close() }()
	return parseProjectLeads(fh)
}

// parseProjectLeads reads the leads file format.
//
//	# project   leads
//	CHTC_Staff  alice, bob %chtc-admins
//	cs101       %cs101-tas
//
// "#" starts a comment anywhere on a line. Leads may be separated by commas,
// whitespace, or both. A project named on several lines gets the union.
// Unusable lines are skipped and reported as warnings rather than failing
// the whole file, so one typo does not revoke every other project's leads.
func parseProjectLeads(r io.Reader) (map[string]*projectLeadEntry, []string, error) {
	entries := make(map[string]*projectLeadEntry)
	var warnings []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})
		if len(fields) == 0 {
			continue
		}
		project := fields[0]
		if !validProjectName(project) {
			warnings = append(warnings, fmt.Sprintf("line %d: project name %q is not usable; skipping the line", lineNo, project))
			continue
		}
		if len(fields) == 1 {
			warnings = append(warnings, fmt.Sprintf("line %d: project %q names no leads", lineNo, project))
			continue
		}
		key := strings.ToLower(project)
		e := entries[key]
		if e == nil {
			e = &projectLeadEntry{project: project}
			entries[key] = e
		}
		for _, lead := range fields[1:] {
			if group, isGroup := strings.CutPrefix(lead, "%"); isGroup {
				if group == "" {
					warnings = append(warnings, fmt.Sprintf("line %d: a bare %% names no group", lineNo))
					continue
				}
				e.groups = append(e.groups, group)
				continue
			}
			e.users = append(e.users, lead)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	return entries, warnings, nil
}

// validProjectName reports whether a name can be used as a project.
//
// Quotes, backslashes and control characters are refused. No sensible
// project is named with them, and refusing them here means a project name
// can only ever become one plain ClassAd string literal in the constraints
// built from it, whichever ClassAd dialect the schedd parses it in.
func validProjectName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r == '"' || r == '\\' || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// sameUser compares a configured lead with the authenticated user,
// case-insensitively.
//
// A bare entry ("bob") is compared the way the rest of the server compares a
// caller with a job's Owner: against the bare form of the actor, so it
// matches bob in any domain. An entry that names a domain ("bob@other.org")
// is compared with the full authenticated username and matches only that
// exact identity: an operator who wrote the domain meant that one, and
// stripping it would grant the lead to every bob in every domain.
func sameUser(configured, actor string) bool {
	configured = strings.TrimSpace(configured)
	actor = strings.TrimSpace(actor)
	if configured == "" {
		return false
	}
	if strings.Contains(configured, "@") {
		return strings.EqualFold(configured, actor)
	}
	return strings.EqualFold(configured, ownerFromActor(actor))
}

func hasGroup(groups []string, want string) bool {
	for _, g := range groups {
		if strings.EqualFold(g, want) {
			return true
		}
	}
	return false
}

// projectFromGroup recovers the project a group grants under pattern, or ""
// when the group does not match it. The fixed parts compare
// case-insensitively, as group names do everywhere else.
func projectFromGroup(pattern, group string) string {
	prefix, suffix, ok := strings.Cut(pattern, projectPlaceholder)
	if !ok || len(group) <= len(prefix)+len(suffix) {
		return ""
	}
	if !strings.EqualFold(group[:len(prefix)], prefix) ||
		!strings.EqualFold(group[len(group)-len(suffix):], suffix) {
		return ""
	}
	project := group[len(prefix) : len(group)-len(suffix)]
	if !validProjectName(project) {
		return ""
	}
	return project
}

// groupForProject is projectFromGroup's inverse: the group whose members
// lead project under pattern.
func groupForProject(pattern, project string) string {
	return strings.Replace(pattern, projectPlaceholder, project, 1)
}

// names reports whether this entry names the user, directly or through one
// of their groups.
func (e *projectLeadEntry) names(username string, groups []string) bool {
	for _, u := range e.users {
		if sameUser(u, username) {
			return true
		}
	}
	for _, g := range e.groups {
		if hasGroup(groups, g) {
			return true
		}
	}
	return false
}

// Leads reports whether the user, holding groups, leads project.
func (p *projectLeads) Leads(project, username string, groups []string) bool {
	if p == nil || !validProjectName(project) {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.snapshotLocked()[strings.ToLower(project)]; e != nil && e.names(username, groups) {
		return true
	}
	if p.pattern != "" && hasGroup(groups, groupForProject(p.pattern, project)) {
		return true
	}
	return false
}

// LedProjects returns every project the user leads, sorted and with
// case-insensitive duplicates removed. Empty means they lead none.
func (p *projectLeads) LedProjects(username string, groups []string) []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	seen := make(map[string]bool)
	var out []string
	add := func(project string) {
		key := strings.ToLower(project)
		if !seen[key] {
			seen[key] = true
			out = append(out, project)
		}
	}
	for _, e := range p.snapshotLocked() {
		if e.names(username, groups) {
			add(e.project)
		}
	}
	if p.pattern != "" {
		for _, g := range groups {
			if project := projectFromGroup(p.pattern, g); project != "" {
				add(project)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i]) < strings.ToLower(out[j]) })
	return out
}

// projectClause is a ClassAd expression matching jobs whose ProjectName is
// one of projects.
//
// Compared with ClassAd "==", which is case-insensitive on strings -- the
// same rule the Go side applies with EqualFold -- and wrapped in "=?= true"
// so a job with no ProjectName (undefined) or a non-string one (error)
// yields false rather than undefined. That matters once the clause is
// combined: "undefined || true" is true, so an undefined here must never
// be left to the surrounding expression to interpret.
//
// No projects matches nothing.
func projectClause(projects []string) string {
	if len(projects) == 0 {
		return "false"
	}
	parts := make([]string, 0, len(projects))
	for _, p := range projects {
		parts = append(parts, fmt.Sprintf("((ProjectName == %s) =?= true)", classadStringLit(p)))
	}
	return "(" + strings.Join(parts, " || ") + ")"
}

// scopeToProjects confines a caller-supplied constraint to jobs in projects,
// on the same terms scopeToOwner confines one to an owner: the constraint is
// parsed and re-serialized before it is ANDed in, so an unbalanced ")" or a
// trailing "|| true" cannot escape the leading clause.
func scopeToProjects(projects []string, constraint string) (string, error) {
	clause := projectClause(projects)
	c := strings.TrimSpace(constraint)
	if c == "" {
		return clause, nil
	}
	safe, err := classadBalanced(c)
	if err != nil {
		return "", fmt.Errorf("constraint is not a valid ClassAd expression: %w", err)
	}
	return fmt.Sprintf("%s && (%s)", clause, safe), nil
}

// scopeToOwnerOrProjects confines a constraint to the caller's own jobs plus
// the jobs in the projects they lead. This is a project lead's read scope,
// and the set a project-scoped bulk action is planned over.
func scopeToOwnerOrProjects(owner string, projects []string, constraint string) (string, error) {
	if owner == "" {
		return "", fmt.Errorf("no owner to scope to")
	}
	clause := fmt.Sprintf("((Owner == %s) || %s)", classadStringLit(owner), projectClause(projects))
	c := strings.TrimSpace(constraint)
	if c == "" {
		return clause, nil
	}
	safe, err := classadBalanced(c)
	if err != nil {
		return "", fmt.Errorf("constraint is not a valid ClassAd expression: %w", err)
	}
	return fmt.Sprintf("%s && (%s)", clause, safe), nil
}

// superuserScope is what an armed session may act on.
type superuserScope struct {
	// Global is HTTP_API_SUPERUSER_GROUP membership: any job.
	Global bool
	// Projects are the projects the caller leads. When Global is false
	// these are the only other users' jobs the caller may act on.
	Projects []string
}

// allowed reports whether this scope permits arming at all.
func (s superuserScope) allowed() bool { return s.Global || len(s.Projects) > 0 }

// leads reports whether project is one of the scope's projects, and returns
// the scope's own spelling of it -- the configured name, which is what
// constraints are built from, rather than whatever the job ad carried.
func (s superuserScope) leads(project string) (string, bool) {
	for _, p := range s.Projects {
		if strings.EqualFold(p, project) {
			return p, true
		}
	}
	return "", false
}
