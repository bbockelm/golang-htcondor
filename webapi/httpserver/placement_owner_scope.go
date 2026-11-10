package httpserver

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/bbockelm/golang-htcondor/webapi/ownerscope"
)

// withPlacementOwnerScope marks ctx so the caller's reads are confined by
// User, the full account name, rather than Owner, when the caller is an
// account condor_placementd assigned: by the browser session behind r, or
// for a bearer (an OAuth2 grant, an API key, a forwarded token) by actor
// being an account a placementd session signed in as. Such an account's
// domain need not be UID_DOMAIN, so its Owner is shared with a local
// user of the same name (see ownerscope.WithUserScope). Everyone else
// keeps Owner scoping.
//
// A failed lookup marks the context: User scoping only ever narrows.
func (h *Handler) withPlacementOwnerScope(ctx context.Context, r *http.Request, actor string) context.Context {
	if r != nil {
		if sd, ok := h.getSessionFromRequest(r); ok {
			if sd.IsPlacementd() {
				return ownerscope.WithUserScope(ctx)
			}
			return ctx
		}
	}
	if h.isPlacementAccount(ctx, actor) {
		return ownerscope.WithUserScope(ctx)
	}
	return ctx
}

// isPlacementAccount reports whether actor is an account a placementd
// session has signed in as (recordPlacementSubject), or the record could
// not be read.
func (h *Handler) isPlacementAccount(ctx context.Context, actor string) bool {
	if h.db == nil || actor == "" {
		return false
	}
	var one int
	err := h.db.QueryRowContext(ctx, `SELECT 1 FROM placement_oauth_subjects WHERE subject = ? LIMIT 1`, actor).Scan(&one)
	return !errors.Is(err, sql.ErrNoRows)
}

// actorClause is the ClassAd clause naming actor's own jobs on ctx's
// terms (ownerscope.OwnerClause): User == actor for a placementd account,
// Owner == its local part for anyone else.
func actorClause(ctx context.Context, actor string) (string, error) {
	return ownerscope.OwnerClause(ctx, actor)
}

// scopeToActor confines an untrusted constraint to actor's own jobs, on
// andScope's terms, by actorClause.
func scopeToActor(ctx context.Context, actor, constraint string) (string, error) {
	clause, err := actorClause(ctx, actor)
	if err != nil {
		return "", err
	}
	return andScope(clause, constraint)
}

// ownerKey is what a view confined to the caller's own jobs is keyed and
// scoped by: the full actor for a placementd account, Owner (the actor's
// local part) for anyone else. It names a cache entry too, so the two
// never share one. ownerKeyClause is the clause for a key it returned.
func ownerKey(ctx context.Context, actor string) string {
	if ownerscope.UserScoped(ctx) {
		return actor
	}
	return ownerFromActor(actor)
}

// ownerKeyClause is the ClassAd clause naming the jobs of key, an
// ownerKey: User == key for a placementd account, Owner == key otherwise.
// key is used as given; a local part may itself contain "@".
func ownerKeyClause(ctx context.Context, key string) string {
	if ownerscope.UserScoped(ctx) {
		return "User == " + classadStringLit(key)
	}
	return "Owner == " + classadStringLit(key)
}

// placementOutsideUIDDomain reports whether the caller is a placementd
// account whose domain is not UID_DOMAIN. The job change feed, and the
// watches and streams built on it, file a job under its Owner alone, so
// for such an account they would carry a same-named local user's jobs;
// they are refused to it instead.
func (h *Handler) placementOutsideUIDDomain(ctx context.Context, actor string) bool {
	if !ownerscope.UserScoped(ctx) {
		return false
	}
	i := strings.LastIndex(actor, "@")
	return i < 0 || h.uidDomain == "" || !strings.EqualFold(actor[i+1:], h.uidDomain)
}
