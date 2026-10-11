package mcpserver

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/apassign"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/multiap"
	"github.com/bbockelm/golang-htcondor/webapi/multiap/multiaptest"
)

func refuseOn(ap string) func(context.Context, apregistry.Member, string) error {
	return func(_ context.Context, m apregistry.Member, _ string) error {
		if m.Name == ap {
			return &multiap.Error{Status: http.StatusForbidden, Reason: multiap.ReasonDenied, Msg: "refused on " + ap}
		}
		return nil
	}
}

// The target AP's verdict on the caller is asked before a submitting tool
// runs, and a refusal submits nothing.
func TestMultiAPSubmitToolsAskTheAPsVerdict(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*multiap.Service)
	}{
		{"Admit", func(svc *multiap.Service) { svc.Admit = refuseOn(mAP2) }},
		{"VerifyCaller", func(svc *multiap.Service) { svc.VerifyCaller = refuseOn(mAP2) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newSubmitAPs(t, "USER alice@d "+mAP2+"\n")
			tc.setup(a.svc)
			for _, c := range submitToolCalls {
				before := a.counts()
				_, err := a.call(callerCtx(t), t, c.tool, c.args)
				if multiap.ReasonOf(err) != multiap.ReasonDenied {
					t.Errorf("%s: %v, want the AP's refusal", c.tool, err)
				}
				if after := a.counts(); after[mAP2] != before[mAP2] {
					t.Errorf("%s: the refusing AP was contacted", c.tool)
				}
			}
			a.mu.Lock()
			defer a.mu.Unlock()
			if len(a.prepared) != 0 {
				t.Errorf("credentials were prepared for a refused submission: %v", a.prepared)
			}
		})
	}
	// A credential tool too.
	a := newSubmitAPs(t, "USER alice@d "+mAP2+"\n")
	a.svc.Admit = refuseOn(mAP2)
	if _, err := a.call(callerCtx(t), t, "list_service_credentials", nil); multiap.ReasonOf(err) != multiap.ReasonDenied {
		t.Errorf("list_service_credentials on a refusing AP: %v", err)
	}
}

func TestMultiAPSubmitToolsNoteTheWrite(t *testing.T) {
	a := newSubmitAPs(t, "USER alice@d "+mAP2+"\n")
	_, _ = a.call(callerCtx(t), t, "submit_job", map[string]any{"submit_file": testSubmitFile})
	if !a.svc.WroteSince(mAP2, time.Minute) || a.svc.WroteSince(mAP1, time.Minute) {
		t.Error("submit_job to ap2 was not noted as a write on ap2 alone")
	}
}

// recordingAssigner answers ap2 and records the kinds it was asked about.
type recordingAssigner struct {
	mu    sync.Mutex
	kinds []string
}

func (r *recordingAssigner) Resolve(_ context.Context, req apassign.Request) (apassign.Assignment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kinds = append(r.kinds, req.Kind)
	return apassign.Assignment{Schedd: mAP2, Source: "test"}, nil
}

func (r *recordingAssigner) Target(ctx context.Context, req apassign.Request, _ string) (string, apassign.Assignment, error) {
	a, err := r.Resolve(ctx, req)
	return a.Schedd, a, err
}

// Each submitting tool asks about its own kind of work.
func TestMultiAPSubmitToolsAskForTheirKind(t *testing.T) {
	a := newSubmitAPs(t, "USER alice@d "+mAP2+"\n")
	for _, c := range submitToolCalls {
		rec := &recordingAssigner{}
		a.svc.Assign = rec
		_, _ = a.call(callerCtx(t), t, c.tool, c.args)
		want := map[string]string{"submit_job": apassign.KindJob, "submit_dag": apassign.KindDAG,
			"build_container": apassign.KindContainerBuild}[c.tool]
		if strings.Join(rec.kinds, ",") != want {
			t.Errorf("%s asked for kinds %v, want %s", c.tool, rec.kinds, want)
		}
	}
}

// An AP that turns untrusted after it was chosen is reported as that.
func TestMultiAPSubmitToolAPTurnsUntrusted(t *testing.T) {
	a := newSubmitAPs(t, "USER alice@d "+mAP2+"\n")
	a.svc.VerifyCaller = func(context.Context, apregistry.Member, string) error {
		a.svc.Registry.(*multiaptest.Registry).Update(mAP2, func(m *apregistry.Member) {
			m.Trust = apregistry.Trust{State: apregistry.TrustUntrusted, Reason: "refused the probe"}
		})
		return nil
	}
	_, err := a.call(callerCtx(t), t, "submit_job", map[string]any{"submit_file": testSubmitFile})
	if multiap.ReasonOf(err) != multiap.ReasonAPUntrusted {
		t.Errorf("got %v, want %s", err, multiap.ReasonAPUntrusted)
	}
}
