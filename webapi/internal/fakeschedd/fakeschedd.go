// Package fakeschedd is a CEDAR schedd for tests: a fixed set of job,
// history and epoch ads behind the commands the job read and action
// paths use.
package fakeschedd

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// Schedd answers QUERY_JOB_ADS(_WITH_AUTH), QUERY_SCHEDD_HISTORY and
// ACT_ON_JOBS by evaluating the request's constraint against its ads the
// way the real schedd does. It applies NO owner filter of its own, which
// is the property that matters to an owner-scoping test: a real schedd
// does not filter job-ad reads by owner either, so whatever this returns
// is exactly what the constraint the client sent admits.
//
// It authenticates TOKEN only, verified with the pool signing key it was
// started with.
type Schedd struct {
	addr string

	mu      sync.Mutex
	jobs    []*classad.ClassAd
	history []*classad.ClassAd
	epochs  []*classad.ClassAd
	// actedOn is every job id an ACT_ON_JOBS request matched.
	actedOn []string
}

// JobAd builds a minimal job ad.
func JobAd(cluster, proc int, owner string, status int) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttr("ClusterId", int64(cluster))
	ad.InsertAttr("ProcId", int64(proc))
	ad.InsertAttrString("Owner", owner)
	ad.InsertAttr("JobStatus", int64(status))
	return ad
}

// Start runs a fake schedd for the life of the test. keyFile is the pool
// signing key (its basename is the key id), trustDomain the token issuer
// it accepts.
func Start(t testing.TB, keyFile, trustDomain string) *Schedd {
	t.Helper()
	f := &Schedd{}
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:             []security.AuthMethod{security.AuthToken},
		Authentication:          security.SecurityRequired,
		CryptoMethods:           []security.CryptoMethod{security.CryptoAES},
		Encryption:              security.SecurityOptional,
		Integrity:               security.SecurityOptional,
		TrustDomain:             trustDomain,
		TokenPoolSigningKeyFile: keyFile,
		SessionCache:            security.NewSessionCache(),
	})
	srv.Handle(commands.QUERY_JOB_ADS, f.queryJobs, "READ")
	srv.Handle(commands.QUERY_JOB_ADS_WITH_AUTH, f.queryJobs, "READ")
	srv.Handle(commands.QUERY_SCHEDD_HISTORY, f.queryHistory, "READ")
	srv.Handle(commands.ACT_ON_JOBS, f.actOnJobs, "WRITE")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	f.addr = fmt.Sprintf("<%s>", ln.Addr().String())
	return f
}

// Addr is the schedd's sinful string.
func (f *Schedd) Addr() string { return f.addr }

// AddJobs adds ads to the queue.
func (f *Schedd) AddJobs(ads ...*classad.ClassAd) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs = append(f.jobs, ads...)
}

// AddHistory adds ads to the job history.
func (f *Schedd) AddHistory(ads ...*classad.ClassAd) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.history = append(f.history, ads...)
}

// AddEpochs adds ads to the epoch history (HistoryRecordSource JOB_EPOCH).
func (f *Schedd) AddEpochs(ads ...*classad.ClassAd) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.epochs = append(f.epochs, ads...)
}

// ActedOn returns the "cluster.proc" ids ACT_ON_JOBS has acted on so far.
func (f *Schedd) ActedOn() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.actedOn...)
}

// matching returns the ads in set that constraint admits. A missing
// constraint admits everything, as on the real schedd.
func matching(set []*classad.ClassAd, constraint *classad.Expr) []*classad.ClassAd {
	var out []*classad.ClassAd
	for _, ad := range set {
		if constraint != nil {
			if ok, _ := constraint.Eval(ad).BoolValue(); !ok {
				continue
			}
		}
		out = append(out, ad)
	}
	return out
}

func readRequest(ctx context.Context, c *cedarserver.Conn) (*classad.ClassAd, error) {
	return message.NewMessageFromStream(c.Stream).GetClassAd(ctx)
}

func sendAd(ctx context.Context, c *cedarserver.Conn, ad *classad.ClassAd) error {
	m := message.NewMessageForStream(c.Stream)
	if err := m.PutClassAd(ctx, ad); err != nil {
		return err
	}
	return m.FinishMessage(ctx)
}

func (f *Schedd) queryJobs(ctx context.Context, c *cedarserver.Conn) error {
	req, err := readRequest(ctx, c)
	if err != nil {
		return err
	}
	constraint, _ := req.Lookup("Requirements")
	f.mu.Lock()
	ads := matching(f.jobs, constraint)
	f.mu.Unlock()
	for _, ad := range ads {
		if err := sendAd(ctx, c, ad); err != nil {
			return err
		}
	}
	final := classad.New()
	final.InsertAttr("Owner", 0)
	return sendAd(ctx, c, final)
}

func (f *Schedd) queryHistory(ctx context.Context, c *cedarserver.Conn) error {
	req, err := readRequest(ctx, c)
	if err != nil {
		return err
	}
	constraint, _ := req.Lookup("Requirements")
	source, _ := req.EvaluateAttrString("HistoryRecordSource")
	f.mu.Lock()
	set := f.history
	if source == "JOB_EPOCH" {
		set = f.epochs
	}
	ads := matching(set, constraint)
	f.mu.Unlock()
	for _, ad := range ads {
		if err := sendAd(ctx, c, ad); err != nil {
			return err
		}
	}
	final := classad.New()
	final.InsertAttr("Owner", 0)
	final.InsertAttr("NumMatches", int64(len(ads)))
	return sendAd(ctx, c, final)
}

// actOnJobs records every job the constraint matches as acted on (hold,
// release or remove -- the fake does not care which) and reports the
// count the way the schedd does: ActionResult OK and the commit
// handshake when something matched, a refusal with zero counts when
// nothing did.
func (f *Schedd) actOnJobs(ctx context.Context, c *cedarserver.Conn) error {
	req, err := readRequest(ctx, c)
	if err != nil {
		return err
	}
	constraint, _ := req.Lookup("ActionConstraint")
	var ads []*classad.ClassAd
	f.mu.Lock()
	if constraint != nil {
		ads = matching(f.jobs, constraint)
	}
	for _, ad := range ads {
		cluster, _ := ad.EvaluateAttrInt("ClusterId")
		proc, _ := ad.EvaluateAttrInt("ProcId")
		f.actedOn = append(f.actedOn, fmt.Sprintf("%d.%d", cluster, proc))
	}
	f.mu.Unlock()

	result := classad.New()
	result.InsertAttr("result_total_1", int64(len(ads)))
	if len(ads) == 0 {
		result.InsertAttr("ActionResult", 0)
		return sendAd(ctx, c, result)
	}
	result.InsertAttr("ActionResult", 1)
	if err := sendAd(ctx, c, result); err != nil {
		return err
	}
	if _, err := message.NewMessageFromStream(c.Stream).GetInt(ctx); err != nil {
		return err
	}
	m := message.NewMessageForStream(c.Stream)
	if err := m.PutInt(ctx, 1); err != nil {
		return err
	}
	return m.FinishMessage(ctx)
}
