package httpserver

import (
	"context"
	"time"
)

// Contexts for work whose result is shared.
//
// A cached answer is served to requests other than the one that produced
// it, so it must not be computed on that one's context. Tying them
// together makes the work's lifetime an accident of whoever happened to
// trigger the refresh: a reload, or the SPA changing a query key,
// cancels that request, and a read that everybody is queued behind dies
// halfway through with "context canceled".
//
// That was reported against the issues page on ap40, where the held-jobs
// read had usually finished by the time the cancellation arrived and the
// run-attempt read had not -- so the answer kept the holds, recorded a
// note blaming the epoch history, and cached it. The dashboard's cached
// queue walk had the same shape, and it is the more expensive read of
// the two.
//
// sharedComputeContext keeps the request's values -- the identity and
// token the schedd handshake needs -- and drops only its cancellation.
// The timeout is what bounds the work instead, since nothing else now
// will. The caller must call the returned cancel.
//
// Both caches call this themselves and hand the result to their compute
// function, rather than leaving each call site to remember: the rule
// belongs to whatever owns the sharing, and the first version of this
// fix -- which left it to the call site -- was written twice and got it
// right once.
func sharedComputeContext(ctx context.Context, limit time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), limit)
}
