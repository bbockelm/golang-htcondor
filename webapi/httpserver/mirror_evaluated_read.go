package httpserver

import (
	"context"
	"errors"

	"github.com/PelicanPlatform/classad/dbrpc"
)

// streamEvaluatedRows streams a projected read whose rows the caller is going
// to EVALUATE, rather than relay.
//
// The distinction decides which opcode is correct. A plain projection returns
// exactly the attributes asked for, which is right for a relay reproducing
// HTCondor's query protocol and wrong for an evaluator: an attribute holding
// an expression over its siblings loses them and evaluates to undefined. On
// these records that is not hypothetical -- RequestMemory is commonly written
// over MemoryUsage, and MemoryUsage over ResidentSetSize -- so the result is a
// plausible wrong number rather than an error. Only the store can compute the
// closure, because whether an attribute holds an expression is a property of
// the stored ad.
//
// reset exists because of how the callers are shaped. They pass their own
// yield, and the accumulator belongs to them -- a decoder, a batch, a slice
// being appended to. A retry re-runs that yield, so without discarding what
// the first attempt produced the rows are counted twice. Taking reset as an
// argument makes that the caller's explicit decision rather than something to
// notice.
//
// A mirror that advertises its features is dispatched directly, with no
// fallback. One that advertises nothing is tried and falls back, which is the
// only thing to do for a server built before the advertisement existed.
func streamEvaluatedRows(ctx context.Context, dbc *dbrpc.Client, table, constraint string,
	attrs []string, limit int, reset func(), yield func(string) bool) error {

	chase := func() error {
		return dbc.QueryRawProjectRefsStream(ctx, table, constraint, attrs, limit, yield)
	}
	plain := func() error {
		return dbc.QueryRawProjectStream(ctx, table, constraint, attrs, limit, yield)
	}
	return dispatchEvaluatedRead(dbc.Supports(dbrpc.FeatProjectRefs), chase, plain, reset)
}

// dispatchEvaluatedRead is streamEvaluatedRows' decision, separated from the
// opcodes so every branch can be tested without a server of the right vintage
// -- the retry needs one too old to implement the opcode, which is exactly the
// peer a current test deployment does not have.
func dispatchEvaluatedRead(support dbrpc.Support, chase, plain func() error, reset func()) error {
	switch support {
	case dbrpc.SupportYes:
		return chase()
	case dbrpc.SupportNo:
		// A definite no. Issuing the request to be refused would spend a round
		// trip learning what we were just told.
		return plain()
	}

	// SupportUnknown: a mirror too old to advertise, which may still implement
	// the opcode -- every feature predates the advertisement. Try it.
	err := chase()
	if errors.Is(err, dbrpc.ErrProjectRefsUnsupported) {
		if reset != nil {
			reset()
		}
		return plain()
	}
	return err
}
