package ownerscope

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// userScopeKey marks a context whose caller is confined by User.
type userScopeKey struct{}

// WithUserScope marks ctx as belonging to a caller whose jobs are named
// by their full user name, owner@domain, and not by Owner.
//
// An account assigned by condor_placementd is such a caller. Its domain
// need not be UID_DOMAIN, and a job's Owner is only the part before the
// "@": bob@course.example and the local bob@UID_DOMAIN share it, so
// confining bob@course.example by Owner would hand it the local bob's
// jobs. The schedd files a job under its User, so that is what such a
// caller is confined by.
func WithUserScope(ctx context.Context) context.Context {
	return context.WithValue(ctx, userScopeKey{}, true)
}

// UserScoped reports whether ctx was marked by WithUserScope.
func UserScoped(ctx context.Context) bool {
	v, _ := ctx.Value(userScopeKey{}).(bool)
	return v
}

// CopyUserScope carries src's mark, if any, onto dst.
func CopyUserScope(dst, src context.Context) context.Context {
	if UserScoped(src) {
		return WithUserScope(dst)
	}
	return dst
}

// OwnerClause is the ClassAd clause naming actor's own jobs: for a
// context marked by WithUserScope, User == actor, the full user name;
// otherwise Owner == the part of actor before its last "@" ("@" is legal
// in a user name). It errors for an actor that names no one.
func OwnerClause(ctx context.Context, actor string) (string, error) {
	if UserScoped(ctx) {
		i := strings.LastIndex(actor, "@")
		if i <= 0 || i == len(actor)-1 {
			return "", errors.New("no authenticated user to scope to")
		}
		return fmt.Sprintf("User == %s", StringLit(actor)), nil
	}
	owner := actor
	if i := strings.LastIndex(actor, "@"); i >= 0 {
		owner = actor[:i]
	}
	if owner == "" {
		return "", errors.New("no authenticated owner to scope to")
	}
	return fmt.Sprintf("Owner == %s", StringLit(owner)), nil
}

// ConstrainActor is Constrain with OwnerClause's clause: constraint ANDed
// onto actor's own jobs, re-serialized so it cannot widen them.
func ConstrainActor(ctx context.Context, actor, constraint string) (string, error) {
	clause, err := OwnerClause(ctx, actor)
	if err != nil {
		return "", err
	}
	c := strings.TrimSpace(constraint)
	if c == "" || strings.EqualFold(c, "true") {
		return clause, nil
	}
	safe, err := Balanced(c)
	if err != nil {
		return "", fmt.Errorf("constraint is not a valid ClassAd expression: %w", err)
	}
	return fmt.Sprintf("(%s) && (%s)", clause, safe), nil
}
