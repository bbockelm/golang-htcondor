package multiap

import (
	"context"
	"net/http"
)

// DefaultFindOwnLimit bounds FindOwn's answer when the caller gives no
// limit.
const DefaultFindOwnLimit = 500

// FindOwn returns the caller's live jobs matching constraint on every AP
// in the set, as the hub holds them, each with at least projection and
// its identity.
//
// It is how the surfaces that keep no record of their own -- interactive
// sessions, apps, browser terminals -- find where the caller's things
// are. Unlike ListJobs it ignores HTTP_API_MULTI_AP_STALE: a degraded
// AP's sessions are still there, and leaving them out would let a second
// session take a name that is already in use. The answer is where to
// look, not what to act on; callers ask the AP itself before acting.
func (s *Service) FindOwn(ctx context.Context, user, constraint string, projection []string, limit int) ([]Row, Sources, error) {
	if user == "" {
		return nil, Sources{}, errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	ctx = s.PinHub(ctx)
	v := s.snapshot(ctx)
	var names []string
	for _, m := range v.members {
		names = append(names, m.Name)
	}
	if len(names) == 0 {
		return nil, v.sources, nil
	}
	scope, err := scoped(user, constraint, names)
	if err != nil {
		return nil, v.sources, err
	}
	if limit <= 0 {
		limit = DefaultFindOwnLimit
	}
	dbc, closer, err := v.hub.Client(ctx)
	if err != nil {
		return nil, v.sources, errorf(http.StatusServiceUnavailable, "the federation hub is unavailable: %v", err)
	}
	defer closer()
	var rows []Row
	var perr error
	err = dbc.QueryRawProjectStream(ctx, TableJobs, scope, projectionWith(projection, keyAttrs...), limit, func(text string) bool {
		row, err := rowFromText(text, "")
		if err != nil {
			perr = err
			return false
		}
		rows = append(rows, row)
		return true
	})
	if s.noteRead(ctx, err) == nil {
		err = perr
	}
	if err != nil {
		return nil, v.sources, errorf(http.StatusServiceUnavailable, "reading the federation hub: %v", err)
	}
	return rows, v.sources, nil
}
