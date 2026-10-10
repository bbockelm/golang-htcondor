// Package fakeschedd is a CEDAR schedd for tests: a fixed set of job,
// history and epoch ads behind the commands the job read and action
// paths use.
package fakeschedd

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"

	"github.com/bbockelm/golang-htcondor/filetransfer"
)

// Schedd answers QUERY_JOB_ADS(_WITH_AUTH), QUERY_SCHEDD_HISTORY,
// ACT_ON_JOBS and TRANSFER_DATA_WITH_PERMS by evaluating the request's constraint against its ads the
// way the real schedd does, and DC_NOP / DC_NOP_READ, which identity
// resolution pings. It applies NO owner filter of its own, which
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
	// sandboxes holds each job's output files, by "cluster.proc".
	sandboxes map[string][]SandboxFile
	// jobQueries counts QUERY_JOB_ADS requests and lastConstraint is the
	// constraint of the latest one.
	jobQueries     int
	lastConstraint string

	// refuseRead makes the schedd refuse every READ-level command; see
	// RefuseRead.
	refuseRead atomic.Bool
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
	sec := &security.SecurityConfig{
		AuthMethods:             []security.AuthMethod{security.AuthToken},
		Authentication:          security.SecurityRequired,
		CryptoMethods:           []security.CryptoMethod{security.CryptoAES},
		Encryption:              security.SecurityOptional,
		Integrity:               security.SecurityOptional,
		TrustDomain:             trustDomain,
		TokenPoolSigningKeyFile: keyFile,
		SessionCache:            security.NewSessionCache(),
	}
	srv := cedarserver.New(sec)
	// A refusal at negotiation: cedar's server answers every
	// authenticated handshake AUTHORIZED and refuses a command only by
	// closing the connection afterwards, which a client that reads
	// nothing back -- a ping -- cannot see. A real schedd says DENIED in
	// the post-auth reply; both reach the client as a failed handshake.
	refused := *sec
	refused.AuthMethods = []security.AuthMethod{security.AuthKerberos}
	srv.SecurityConfigForCommand = func(cmd int) *security.SecurityConfig {
		if f.refuseRead.Load() && readLevel(cmd) {
			return &refused
		}
		return nil
	}
	nop := func(context.Context, *cedarserver.Conn) error { return nil }
	srv.Handle(commands.DC_NOP, nop, "ALLOW")
	srv.Handle(commands.DC_NOP_READ, nop, "READ")
	srv.Handle(commands.QUERY_JOB_ADS, f.queryJobs, "READ")
	srv.Handle(commands.QUERY_JOB_ADS_WITH_AUTH, f.queryJobs, "READ")
	srv.Handle(commands.QUERY_SCHEDD_HISTORY, f.queryHistory, "READ")
	srv.Handle(commands.ACT_ON_JOBS, f.actOnJobs, "WRITE")
	srv.Handle(commands.TRANSFER_DATA_WITH_PERMS, f.transferData, "WRITE")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	f.addr = fmt.Sprintf("<%s>", ln.Addr().String())
	return f
}

// Addr is the schedd's sinful string.
func (f *Schedd) Addr() string { return f.addr }

// RefuseRead makes the schedd refuse every READ-level command (DC_NOP_READ
// and the job and history queries) while still authenticating callers
// and answering DC_NOP, as a schedd whose READ authorization excludes the
// caller does. It applies to every caller.
func (f *Schedd) RefuseRead(refuse bool) { f.refuseRead.Store(refuse) }

// readLevel reports whether cmd is one of the READ-level commands this
// schedd answers.
func readLevel(cmd int) bool {
	switch cmd {
	case commands.DC_NOP_READ, commands.QUERY_JOB_ADS, commands.QUERY_JOB_ADS_WITH_AUTH, commands.QUERY_SCHEDD_HISTORY:
		return true
	}
	return false
}

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

// SandboxFile is one file in a job's output sandbox. Open supplies its
// Size bytes each time the sandbox is transferred.
type SandboxFile struct {
	Name string
	Size int64
	Open func() io.ReadCloser
}

// AddSandbox sets the output files TRANSFER_DATA_WITH_PERMS sends for job
// cluster.proc.
func (f *Schedd) AddSandbox(cluster, proc int, files ...SandboxFile) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sandboxes == nil {
		f.sandboxes = map[string][]SandboxFile{}
	}
	f.sandboxes[fmt.Sprintf("%d.%d", cluster, proc)] = files
}

// JobQueries reports how many job-ad queries the schedd has answered and
// the constraint of the latest.
func (f *Schedd) JobQueries() (int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jobQueries, f.lastConstraint
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
	f.jobQueries++
	if constraint != nil {
		f.lastConstraint = constraint.String()
	}
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

// transferData answers TRANSFER_DATA_WITH_PERMS the way the schedd does
// for a tool fetching output: the count of matching jobs, then each job's
// ad followed by a file-transfer upload of its sandbox, then the tool's
// OK reply.
func (f *Schedd) transferData(ctx context.Context, c *cedarserver.Conn) error {
	in := message.NewMessageFromStream(c.Stream)
	if _, err := in.GetString(ctx); err != nil { // version
		return err
	}
	text, err := in.GetString(ctx)
	if err != nil {
		return err
	}
	constraint, err := classad.ParseExpr(text)
	if err != nil {
		return err
	}
	f.mu.Lock()
	ads := matching(f.jobs, constraint)
	f.mu.Unlock()

	out := message.NewMessageForStream(c.Stream)
	if err := out.PutInt32(ctx, int32(len(ads))); err != nil { //nolint:gosec // a test queue is small
		return err
	}
	if err := out.FinishMessage(ctx); err != nil {
		return err
	}
	opts := filetransfer.Options{}
	for _, ad := range ads {
		if err := sendAd(ctx, c, ad); err != nil {
			return err
		}
		cluster, _ := ad.EvaluateAttrInt("ClusterId")
		proc, _ := ad.EvaluateAttrInt("ProcId")
		f.mu.Lock()
		files := f.sandboxes[fmt.Sprintf("%d.%d", cluster, proc)]
		f.mu.Unlock()
		var size int64
		for _, sf := range files {
			size += sf.Size
		}
		if err := filetransfer.SendPreamble(ctx, c.Stream, size, false, opts); err != nil {
			return err
		}
		state := &filetransfer.SendState{}
		for _, sf := range files {
			open := sf.Open
			spec := filetransfer.FileSpec{
				WireName: sf.Name,
				Mode:     0o644,
				Size:     sf.Size,
				Open:     func() (io.ReadCloser, error) { return open(), nil },
			}
			if err := filetransfer.SendFile(ctx, c.Stream, spec, state, opts); err != nil {
				return err
			}
		}
		// The tool's receiver performs no TransferAck exchange, so
		// CommandFinished alone ends this job's files.
		done := message.NewMessageForStream(c.Stream)
		if err := done.PutInt32(ctx, int32(filetransfer.CmdFinished)); err != nil {
			return err
		}
		if err := done.FinishMessage(ctx); err != nil {
			return err
		}
	}
	_, err = message.NewMessageFromStream(c.Stream).GetInt32(ctx)
	return err
}
