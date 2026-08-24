package dbmirror

import (
	"testing"

	"github.com/PelicanPlatform/classad/dbrpc"
)

// TestCursorRoundTrip is the property the whole pagination scheme rests
// on: what the mirror hands out on page N must come back byte-identical
// on page N+1, or the resumed scan restarts somewhere else.
func TestCursorRoundTrip(t *testing.T) {
	for _, want := range []dbrpc.SeqCursor{
		{},
		{Shard: 3, Snapshot: 918273645, Seq: 42, Key: "12.7"},
		// Keys are opaque bytes; a token must survive ones that would
		// break a delimiter-based encoding.
		{Shard: 1, Key: "a:b,c\"d\\e\nf"},
	} {
		tok := EncodeCursor(want)
		if !IsCursor(tok) {
			t.Fatalf("EncodeCursor(%+v) = %q, which IsCursor does not recognize", want, tok)
		}
		got, err := DecodeCursor(tok)
		if err != nil {
			t.Fatalf("DecodeCursor(%q): %v", tok, err)
		}
		if got != want {
			t.Errorf("round trip: got %+v, want %+v", got, want)
		}
	}
}

// TestIsCursorRejectsForeignTokens keeps the two backends' tokens apart.
// The schedd's is a base64 "cluster.proc"; mistaking one for a mirror
// cursor would resume a scan the caller never started.
func TestIsCursorRejectsForeignTokens(t *testing.T) {
	for _, tok := range []string{
		"",
		"MTIzLjQ=", // a schedd token: base64 of "123.4"
		"db1",      // prefix without the separator
		"DB1:abc",  // the prefix is not case-insensitive
	} {
		if IsCursor(tok) {
			t.Errorf("IsCursor(%q) = true, want false", tok)
		}
	}
}

// TestDecodeCursorRejectsGarbage: a token that claims to be ours and is
// not readable must be an error, never a zero cursor, because a zero
// cursor silently restarts the walk from the top and re-serves rows the
// caller already has.
func TestDecodeCursorRejectsGarbage(t *testing.T) {
	for _, tok := range []string{
		"db1:",
		"db1:!!!not-base64!!!",
		"db1:bm90LWpzb24=", // valid base64, "not-json"
		"MTIzLjQ=",         // a schedd token
	} {
		if c, err := DecodeCursor(tok); err == nil {
			t.Errorf("DecodeCursor(%q) = %+v, want an error", tok, c)
		}
	}
}

// TestJobsDecisionOwnsItsOwnTokens: the mirror resumes a token it
// issued and declines one the schedd issued, so neither backend
// continues the other's walk.
func TestJobsDecisionOwnsItsOwnTokens(t *testing.T) {
	now := int64(1_700_000_000)
	fresh := &Info{Name: "db", Address: "<1.2.3.4:9618>", JobQueueCaughtUp: true, JobQueueLastSyncTime: now - 5}

	if d := JobsDecision(fresh, "", now); !d.Use {
		t.Error("a first page should route to a current mirror")
	}
	if d := JobsDecision(fresh, EncodeCursor(dbrpc.SeqCursor{Shard: 2, Seq: 9}), now); !d.Use {
		t.Error("a mirror-issued token should resume on the mirror")
	}
	// A schedd-issued token is a query-shape decline, not an
	// availability one: retrying will not help, the caller has to drop
	// the token.
	d := JobsDecision(fresh, "MTIzLjQ=", now)
	if d.Use {
		t.Errorf("a schedd-issued token must stay with the schedd, got ok (%s)", d.Note)
	}
	if d.Reason != ReasonPageToken {
		t.Errorf("Reason = %q, want %q", d.Reason, ReasonPageToken)
	}
}
