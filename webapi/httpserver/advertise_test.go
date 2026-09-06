package httpserver

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// TestMirrorStatusForAd checks the health distillation used in the collector ad:
// a dial or token failure is NOT healthy (this is exactly the ap40 breakage we
// want visible pool-wide), and the reason is surfaced in Status.
func TestMirrorStatusForAd(t *testing.T) {
	if got := mirrorStatusForAd(dbmirror.Health{Enabled: false}); got.Enabled || got.Healthy {
		t.Errorf("disabled mirror: %+v", got)
	}

	dial := mirrorStatusForAd(dbmirror.Health{Enabled: true, LastDialError: "connection reset"})
	if dial.Healthy {
		t.Error("a dial error must not be reported healthy")
	}
	if dial.Status == "" || dial.Status == "ok" {
		t.Errorf("dial error should surface a reason, got %q", dial.Status)
	}

	tok := mirrorStatusForAd(dbmirror.Health{Enabled: true, TokenError: "minting failed"})
	if tok.Healthy {
		t.Error("a token error must not be reported healthy")
	}

	ok := mirrorStatusForAd(dbmirror.Health{Enabled: true})
	if !ok.Healthy || ok.Status != "ok" {
		t.Errorf("clean mirror should be healthy/ok, got %+v", ok)
	}
}
