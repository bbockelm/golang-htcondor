package httpserver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
)

// defaultMaxRequestBody is the most any request body may carry unless its
// route says otherwise with setBodyLimit. It is installed once, in
// Handler.ServeHTTP, so a route added later is bounded without doing
// anything; before it, every JSON route decoded a body of any size, and
// most of them did so before the caller's credential had been checked.
//
// A JSON request this API understands is a few kilobytes. A megabyte
// leaves room for a large submit file or a long list of job ids.
const defaultMaxRequestBody = 1 << 20

// requestBodyLimit is what ServeHTTP shares between a request's body and
// its response writer: whether the body ran past its limit, and what the
// limit was. The response writer reads it to answer 413 however the
// handler went on to describe the failed read.
type requestBodyLimit struct {
	// exceeded is the limit the body ran past, or 0 while it has not.
	// Atomic because some routes read the body on another goroutine
	// (a spooled tar is streamed to the schedd) than the one that
	// writes the response.
	exceeded atomic.Int64
}

// Exceeded returns the limit the body ran past, or 0 if it has not.
func (l *requestBodyLimit) Exceeded() int64 {
	if l == nil {
		return 0
	}
	return l.exceeded.Load()
}

// limitedBody is a request body behind http.MaxBytesReader that also
// remembers the body it wraps, so setBodyLimit can replace the limit
// instead of stacking a second one on top. Stacked MaxBytesReaders take
// the smaller limit, which would leave every route capped at the
// default no matter what it asked for.
type limitedBody struct {
	orig  io.ReadCloser // the request's own body, unbounded
	rc    io.ReadCloser // orig behind http.MaxBytesReader
	state *requestBodyLimit
}

func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			b.state.exceeded.Store(tooLarge.Limit)
		}
	}
	return n, err
}

func (b *limitedBody) Close() error { return b.rc.Close() }

// limitRequestBody puts the default limit on r's body. ServeHTTP calls it
// for every request; nothing else should.
func limitRequestBody(w http.ResponseWriter, r *http.Request, state *requestBodyLimit) {
	if r.Body == nil || r.Body == http.NoBody {
		return
	}
	r.Body = &limitedBody{
		orig:  r.Body,
		rc:    http.MaxBytesReader(w, r.Body, defaultMaxRequestBody),
		state: state,
	}
}

// setBodyLimit replaces the limit on r's body with n bytes. A route that
// needs a different limit than defaultMaxRequestBody calls this before
// it reads the body -- larger for uploads, smaller where a few kilobytes
// is all the route can mean.
//
// Use this and not http.MaxBytesReader in a handler. Wrapping the body
// again only ever lowers the limit, and an overflow it reports does not
// reach the response writer, so it would surface as whatever status the
// handler picks for a bad body rather than 413.
func setBodyLimit(w http.ResponseWriter, r *http.Request, n int64) {
	lb, ok := r.Body.(*limitedBody)
	if !ok {
		// Not reached through ServeHTTP (or no body at all): limit what
		// is there.
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, n)
		}
		return
	}
	r.Body = &limitedBody{
		orig:  lb.orig,
		rc:    http.MaxBytesReader(w, lb.orig, n),
		state: lb.state,
	}
}

// removeBodyLimit takes the limit off r's body. Only for a reverse proxy,
// which streams the body to its upstream rather than holding it: an
// upload into a notebook or editor running in a job is the user's own
// business, and its size is the job's to bound.
func removeBodyLimit(r *http.Request) {
	if lb, ok := r.Body.(*limitedBody); ok {
		r.Body = lb.orig
	}
}

// bodyLimitExceeded returns the limit the request's body ran past, or 0,
// by finding the writer ServeHTTP installed beneath w.
func bodyLimitExceeded(w http.ResponseWriter) int64 {
	for w != nil {
		if bw, ok := w.(*bodyLimitWriter); ok {
			return bw.body.Exceeded()
		}
		u, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			return 0
		}
		w = u.Unwrap()
	}
	return 0
}

// bodyLimitWriter turns any error status into 413 once the request body
// has run past its limit. Handlers report a failed read as 400 or 500, and
// neither tells the client that sending less would work.
//
// It records nothing and decides nothing else. Hijack and Flush are
// forwarded because embedding http.ResponseWriter does not promote them,
// and the WebSocket upgraders and streaming handlers assert them on the
// writer they are given; Unwrap lets http.NewResponseController and
// bodyLimitExceeded see through it.
type bodyLimitWriter struct {
	http.ResponseWriter
	body *requestBodyLimit
}

func (b *bodyLimitWriter) WriteHeader(code int) {
	if code >= 400 && b.body.Exceeded() > 0 {
		code = http.StatusRequestEntityTooLarge
	}
	b.ResponseWriter.WriteHeader(code)
}

func (b *bodyLimitWriter) Unwrap() http.ResponseWriter { return b.ResponseWriter }

func (b *bodyLimitWriter) Flush() {
	_ = http.NewResponseController(b.ResponseWriter).Flush()
}

func (b *bodyLimitWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := b.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("bodyLimitWriter: underlying ResponseWriter (%T) does not implement http.Hijacker", b.ResponseWriter)
	}
	return hj.Hijack()
}

var (
	_ http.Hijacker = (*bodyLimitWriter)(nil)
	_ http.Flusher  = (*bodyLimitWriter)(nil)
)
