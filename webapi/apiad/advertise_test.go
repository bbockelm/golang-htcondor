package apiad

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func TestAddAttrsCoreAndMirror(t *testing.T) {
	ad := classad.New()
	AddAttrs(ad, Input{
		Endpoint:      "https://ap40.example.org/",
		ScheddName:    "ap40",
		ScheddAddress: "10.0.0.1:9618?sock=schedd_1_abcd", // must be angle-wrapped in the ad
		TrustDomain:   "flock.opensciencegrid.org",
		MCPEnabled:    true,
		ActiveStreams: 3,
		Mirror:        MirrorStatus{Enabled: true, Healthy: true, StalenessSeconds: 12, Status: "ok"},
	})

	if v, _ := ad.EvaluateAttrString("HTTPEndpoint"); v != "https://ap40.example.org/" {
		t.Errorf("HTTPEndpoint = %q", v)
	}
	if v, _ := ad.EvaluateAttrString("ScheddAddress"); v != "<10.0.0.1:9618?sock=schedd_1_abcd>" {
		t.Errorf("ScheddAddress not angle-wrapped: %q", v)
	}
	if v, ok := ad.EvaluateAttrBool("MCPEnabled"); !ok || !v {
		t.Errorf("MCPEnabled = %v,%v", v, ok)
	}
	if v, ok := ad.EvaluateAttrInt("ActiveWatchStreams"); !ok || v != 3 {
		t.Errorf("ActiveWatchStreams = %v,%v", v, ok)
	}
	if v, ok := ad.EvaluateAttrBool("HTCondorDBMirrorHealthy"); !ok || !v {
		t.Errorf("HTCondorDBMirrorHealthy = %v,%v", v, ok)
	}
	if v, ok := ad.EvaluateAttrInt("HTCondorDBMirrorStalenessSeconds"); !ok || v != 12 {
		t.Errorf("staleness = %v,%v", v, ok)
	}
}

// When the mirror is disabled, only the Enabled=false flag is written -- no
// staleness/health noise for an integration that is not in use.
func TestAddAttrsMirrorDisabledIsQuiet(t *testing.T) {
	ad := classad.New()
	AddAttrs(ad, Input{Mirror: MirrorStatus{Enabled: false}})
	if v, ok := ad.EvaluateAttrBool("HTCondorDBMirrorEnabled"); !ok || v {
		t.Errorf("HTCondorDBMirrorEnabled = %v,%v, want false", v, ok)
	}
	if _, ok := ad.EvaluateAttrInt("HTCondorDBMirrorStalenessSeconds"); ok {
		t.Error("staleness should be absent when the mirror is disabled")
	}
	if _, ok := ad.EvaluateAttrBool("HTCondorDBMirrorHealthy"); ok {
		t.Error("healthy flag should be absent when the mirror is disabled")
	}
}

// Empty optionals are omitted rather than written as empty strings.
func TestAddAttrsOmitsEmpty(t *testing.T) {
	ad := classad.New()
	AddAttrs(ad, Input{})
	for _, attr := range []string{"HTTPEndpoint", "ScheddName", "ScheddAddress", "TrustDomain"} {
		if _, ok := ad.EvaluateAttrString(attr); ok {
			t.Errorf("%s should be omitted when empty", attr)
		}
	}
}
