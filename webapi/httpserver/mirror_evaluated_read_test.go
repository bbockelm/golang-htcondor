package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/db"
	"github.com/PelicanPlatform/classad/dbrpc"
)

// The corpus is the point. MemoryUsage is stored as an expression over
// ResidentSetSize, which is how a schedd writes it, and only "MemoryUsage" is
// projected. With the closure the sibling comes along and the attribute
// evaluates; without it the attribute is undefined. A corpus of literals
// passes either way and would prove nothing -- which is exactly how a
// regression here would ship green.
const (
	memoryUsageExpr = "((ResidentSetSize + 1023) / 1024)"
	seedRows        = 4
)

// projTestServer serves a mutable "jobs" table of expression-valued ads over
// an in-process pipe, and returns a dialer for clients of varying vintage.
func projTestServer(t *testing.T) func(attrs map[string]string) *dbrpc.Client {
	t.Helper()

	cat, err := db.OpenCatalog(t.TempDir())
	if err != nil {
		t.Fatalf("open catalog: %v", err)
	}
	if _, err := cat.CreateTable("jobs"); err != nil {
		t.Fatalf("create jobs: %v", err)
	}
	rpc := dbrpc.NewServerCatalog(cat)
	t.Cleanup(func() { rpc.Close(); _ = cat.Close() })

	dial := func(attrs map[string]string) *dbrpc.Client {
		cconn, sconn := net.Pipe()
		go func() { _ = rpc.ServeConn(dbrpc.NewStreamConn(sconn)) }()
		c := dbrpc.NewClient(dbrpc.NewStreamConn(cconn), dbrpc.WithPeerSessionAttrs(attrs))
		t.Cleanup(func() { _ = c.Close() })
		return c
	}

	ctx := context.Background()
	seed := dial(nil)
	tx, err := seed.BeginTable(ctx, "jobs")
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	for i := range seedRows {
		ad := fmt.Sprintf("ClusterId = %d\nProcId = 0\nResidentSetSize = %d\nMemoryUsage = %s",
			100+i, 2048*(i+1), memoryUsageExpr)
		if err := tx.NewClassAd(ctx, fmt.Sprintf("%d.0", 100+i), ad); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return dial
}

// readMemoryUsage runs the helper for a projection of MemoryUsage alone and
// reports how many rows evaluated it to a number.
func readMemoryUsage(t *testing.T, dbc *dbrpc.Client) (rows, evaluated int, err error) {
	t.Helper()
	err = streamEvaluatedRows(context.Background(), dbc, "jobs", "true",
		[]string{"MemoryUsage"}, 0,
		func() { rows, evaluated = 0, 0 },
		func(row string) bool {
			rows++
			ad, perr := classad.ParseOld(row)
			if perr != nil {
				t.Errorf("parsing %q: %v", row, perr)
				return false
			}
			if _, ok := ad.EvaluateAttrNumber("MemoryUsage"); ok {
				evaluated++
			}
			return true
		})
	return rows, evaluated, err
}

// TestAdvertisedPeerGetsTheClosure: a mirror that says it has the
// reference-chasing projection is sent that request, and the rows evaluate.
func TestAdvertisedPeerGetsTheClosure(t *testing.T) {
	dial := projTestServer(t)
	rows, evaluated, err := readMemoryUsage(t, dial(dbrpc.ServerSessionAttrs()))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if rows != seedRows {
		t.Fatalf("got %d rows, want %d", rows, seedRows)
	}
	if evaluated != seedRows {
		t.Errorf("%d of %d rows evaluated MemoryUsage; the closure did not come back", evaluated, rows)
	}
}

// TestPeerWithoutTheFeatureIsNotAsked is the other half, and the one that
// proves the dispatch is real rather than always taking one path: a mirror
// that advertises its features and omits this one is sent the plain
// projection, whose rows cannot evaluate. Seeing undefined here is the
// correct, honest outcome -- and it is also what the SupportYes case would
// look like if the dispatch were broken.
func TestPeerWithoutTheFeatureIsNotAsked(t *testing.T) {
	dial := projTestServer(t)
	noRefs := map[string]string{
		dbrpc.SessionAttrProtocol: "1",
		dbrpc.SessionAttrFeatures: string(dbrpc.FeatTopK),
	}
	rows, evaluated, err := readMemoryUsage(t, dial(noRefs))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if rows != seedRows {
		t.Fatalf("got %d rows, want %d", rows, seedRows)
	}
	if evaluated != 0 {
		t.Errorf("%d rows evaluated MemoryUsage without the closure; the two paths are indistinguishable "+
			"and this corpus proves nothing", evaluated)
	}
}

// TestSilentPeerIsTried: a mirror too old to advertise may still implement the
// opcode, so it is tried rather than written off. Treating silence as a
// refusal would quietly downgrade every mirror older than the advertisement.
func TestSilentPeerIsTried(t *testing.T) {
	dial := projTestServer(t)
	rows, evaluated, err := readMemoryUsage(t, dial(nil))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if evaluated != rows || rows != seedRows {
		t.Errorf("got %d/%d rows evaluated; a silent peer that implements the opcode should have been asked",
			evaluated, rows)
	}
}

// TestDispatchBranches covers the decision itself. The retry branch needs a
// peer too old to implement the opcode, which no current server is, so the
// branch is tested here rather than against a server -- the three tests above
// prove the opcodes it dispatches to behave as it assumes.
func TestDispatchBranches(t *testing.T) {
	for _, tc := range []struct {
		name       string
		support    dbrpc.Support
		chaseErr   error
		wantChase  int
		wantPlain  int
		wantResets int
		wantErrIs  error
	}{
		{"advertised: no fallback path at all", dbrpc.SupportYes, nil, 1, 0, 0, nil},
		{"advertised without it: never asked", dbrpc.SupportNo, nil, 0, 1, 0, nil},
		{"silent peer that has it: tried, kept", dbrpc.SupportUnknown, nil, 1, 0, 0, nil},
		{"silent peer that lacks it: retried after a reset", dbrpc.SupportUnknown,
			dbrpc.ErrProjectRefsUnsupported, 1, 1, 1, nil},
		{"a real failure is not a fallback", dbrpc.SupportUnknown, errBoom, 1, 0, 0, errBoom},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chases, plains, resets := 0, 0, 0
			err := dispatchEvaluatedRead(tc.support,
				func() error { chases++; return tc.chaseErr },
				func() error { plains++; return nil },
				func() { resets++ })

			if chases != tc.wantChase || plains != tc.wantPlain {
				t.Errorf("chase=%d plain=%d, want chase=%d plain=%d", chases, plains, tc.wantChase, tc.wantPlain)
			}
			if resets != tc.wantResets {
				t.Errorf("reset called %d times, want %d: a retry that does not discard the first "+
					"attempt counts every row twice", resets, tc.wantResets)
			}
			if tc.wantErrIs == nil && err != nil {
				t.Errorf("err = %v, want nil", err)
			}
			if tc.wantErrIs != nil && !errors.Is(err, tc.wantErrIs) {
				t.Errorf("err = %v, want %v", err, tc.wantErrIs)
			}
		})
	}
}

// TestNilResetIsNotAPanic: reset is optional for a caller with nothing to
// undo, and a nil must not take the daemon down on the retry path.
func TestNilResetIsNotAPanic(t *testing.T) {
	err := dispatchEvaluatedRead(dbrpc.SupportUnknown,
		func() error { return dbrpc.ErrProjectRefsUnsupported },
		func() error { return nil }, nil)
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

var errBoom = errors.New("the read failed for its own reasons")
