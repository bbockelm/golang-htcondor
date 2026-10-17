package httpserver

import (
	"context"
	"net/http"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/issues"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
)

// multiAPIssueScope is the issues view's scope and source in multi-AP
// mode: the caller's jobs on every AP (or ?schedd=), narrowed by
// constraint (already re-serialized), read from the hub.
func (s *Handler) multiAPIssueScope(ctx context.Context, r *http.Request, constraint string, includeEnded bool) (string, issues.Source, *multiap.Sources, error) {
	user, err := s.multi.svc.UserFor(htcondor.GetAuthenticatedUserFromContext(ctx))
	if err != nil {
		return "", nil, nil, err
	}
	schedd := ""
	if r != nil {
		schedd = r.URL.Query().Get("schedd")
	}
	scope, _, sources, err := s.multi.svc.Scope(ctx, user, constraint, schedd)
	if err != nil {
		return "", nil, nil, err
	}
	sources = s.multi.svc.TableSources(ctx, sources, multiap.TableJobs)
	if includeEnded {
		sources = s.multi.svc.TableSources(ctx, sources, multiap.TableEpochHistory)
	}
	return scope, multiap.IssueSource{Service: s.multi.svc}, &sources, nil
}
