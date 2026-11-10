package chat

import (
	"context"
	"strings"
)

// Scope values. A page requests ScopeMine or ScopeEveryone in
// Request.Scope; the server resolves that request into one of the three
// effective scopes below and puts the result on the context the engine
// and the tools run under (WithScope).
const (
	ScopeMine     = "mine"
	ScopeEveryone = "everyone"
	// ScopeProjects is only ever a resolved scope: a project lead asking
	// for everyone's jobs gets their own plus their projects'.
	ScopeProjects = "projects"
)

// RequestedScope normalizes the scope a page asked for. Anything other
// than "everyone" -- empty, unknown, mistyped -- is "mine".
func RequestedScope(s string) string {
	if s == ScopeEveryone {
		return ScopeEveryone
	}
	return ScopeMine
}

// Scope is the server's resolution of the scope a page asked for: which
// users' jobs the tools may read, and whether they may act on other
// users' jobs. Only the server builds one; nothing a browser sends is
// copied into it except, normalized, Requested.
type Scope struct {
	// Requested is what the page asked for: ScopeMine or ScopeEveryone.
	Requested string `json:"requested"`
	// Effective is what the caller gets: ScopeMine, ScopeEveryone or
	// ScopeProjects.
	Effective string `json:"scope"`
	// Projects are the projects a ScopeProjects caller leads.
	Projects []string `json:"projects,omitempty"`
	// ActOnOthers reports whether the job-changing tools may act on
	// other users' jobs. Only ever true with Effective == ScopeEveryone.
	ActOnOthers bool `json:"act_on_others"`
}

// Mine is the scope of a caller confined to their own jobs.
func Mine(requested string) Scope {
	return Scope{Requested: RequestedScope(requested), Effective: ScopeMine}
}

// Confined reports whether the tools see only the caller's own jobs.
func (s Scope) Confined() bool {
	return s.Effective != ScopeEveryone && s.Effective != ScopeProjects
}

// Denied reports whether the page asked for everyone's jobs and the
// caller was confined to their own.
func (s Scope) Denied() bool {
	return s.Requested == ScopeEveryone && s.Confined()
}

type scopeKey struct{}

// WithScope returns ctx carrying the resolved scope.
func WithScope(ctx context.Context, s Scope) context.Context {
	return context.WithValue(ctx, scopeKey{}, s)
}

// ScopeFrom returns the resolved scope on ctx. A context without one is
// confined to the caller's own jobs: forgetting to resolve a scope can
// only ever narrow what the tools see.
func ScopeFrom(ctx context.Context) Scope {
	s, ok := ctx.Value(scopeKey{}).(Scope)
	if !ok || (s.Effective != ScopeEveryone && s.Effective != ScopeProjects) {
		requested := ScopeMine
		if ok {
			requested = RequestedScope(s.Requested)
		}
		return Mine(requested)
	}
	if s.Effective != ScopeEveryone {
		s.ActOnOthers = false
	}
	return s
}

// promptStatement is the system-prompt paragraph that tells the model
// which jobs its tools cover. It is built from the resolved scope only.
func (s Scope) promptStatement() string {
	switch s.Effective {
	case ScopeEveryone:
		var b strings.Builder
		b.WriteString(`Scope: the user is an administrator viewing EVERY user's jobs, and your job tools
cover every user's jobs. Results carry each job's Owner. Whenever you talk about a job
that is not the user's own, name its owner.
`)
		if s.ActOnOthers {
			b.WriteString(`Actions you take on another user's job act on that user's work: say whose job it is
before proposing one. Every action asks the user to confirm, and the confirmation names
the job's owner.
`)
		} else {
			b.WriteString(`You can read other users' jobs but act only on the user's own; an action on another
user's job is refused.
`)
		}
		return b.String()
	case ScopeProjects:
		return `Scope: your job tools cover the user's own jobs and the jobs of the projects they lead
(` + strings.Join(s.Projects, ", ") + `). Results carry each job's Owner; name the owner whenever you
talk about a job that is not the user's own. You can act only on the user's own jobs.
`
	}
	if s.Requested == ScopeEveryone {
		return `Scope: the page asked for every user's jobs, but this user may see only their own, so
your tools cover ONLY the user's own jobs. If the user asks about other users' jobs, say
that their own jobs are all you can see.
`
	}
	return `Scope: every tool you call is silently scoped to the authenticated user's own jobs.
You CANNOT see or act on other users' jobs even if asked. If the user asks you to,
explain that and suggest an alternative.
`
}
