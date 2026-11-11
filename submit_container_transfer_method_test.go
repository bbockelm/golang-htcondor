package htcondor

import (
	"strings"
	"testing"
)

// adForBehavior builds a job ad under an explicit release behavior, since
// the zero SubmitBehavior is the oldest one.
func adForBehavior(t *testing.T, b SubmitBehavior, src string) map[string]string {
	t.Helper()
	sf, err := ParseSubmitFileWithOptions(strings.NewReader(src), SubmitParseOptions{Behavior: b})
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd %q: %v", src, err)
	}
	out := map[string]string{}
	for _, name := range ad.GetAttributes() {
		if expr, ok := ad.Lookup(name); ok && expr != nil {
			out[name] = expr.String()
		}
	}
	return out
}

// TestContainerSourceIsATransferMethod covers the Requirements clause a
// container job needs for the plugin that fetches its image.
//
// A container image in a common catalog never reaches TransferInput, so the
// scheme it is fetched with is invisible to the loop that derives the
// methods from the input files. HTCONDOR-3932 added ContainerImageSource as
// a source of its own, and without it a job matched machines with no plugin
// for its image and failed the transfer there.
func TestContainerSourceIsATransferMethod(t *testing.T) {
	const newest = "26.2.0"
	b := SubmitBehaviorFor(newest)
	if !b.ContainerSourceIsATransferMethod {
		t.Fatalf("SubmitBehaviorFor(%q) does not have the behavior under test", newest)
	}

	// The ad renders a call with a space after the comma, which the
	// differential harness's Unparse does not; match on the argument.
	clause := func(method string) string {
		return `stringListIMember("` + method + `", TARGET.HasFileTransferPluginMethods)`
	}

	t.Run("a scheme that needs a plugin", func(t *testing.T) {
		// Not a URL -- there is no "//" -- so the image is transferred by
		// path and the loop over TransferInput never sees the scheme.
		ad := adForBehavior(t, b, "universe = container\ncontainer_image = foo:bar.sif\nqueue\n")
		if got := ad["ContainerImageSource"]; got != `"foo"` {
			t.Fatalf("ContainerImageSource = %s, want \"foo\"", got)
		}
		if !strings.Contains(ad["Requirements"], clause("foo")) {
			t.Errorf("Requirements = %s, want it to carry %s", ad["Requirements"], clause("foo"))
		}
		if got := ad["WantTransferPluginMethods"]; got != `"foo"` {
			t.Errorf("WantTransferPluginMethods = %s, want \"foo\"", got)
		}
	})

	t.Run("the four sources that need no plugin", func(t *testing.T) {
		for _, img := range []string{"docker://busybox", "oras://example.com/i:1"} {
			ad := adForBehavior(t, b, "universe = container\ncontainer_image = "+img+"\nqueue\n")
			if strings.Contains(ad["Requirements"], "HasFileTransferPluginMethods") {
				t.Errorf("%s: Requirements = %s, want no plugin clause", img, ad["Requirements"])
			}
		}
		// A plain path is fetched over cedar, HTCondor's own transfer.
		ad := adForBehavior(t, b, "universe = container\ncontainer_image = image.sif\nqueue\n")
		if got := ad["ContainerImageSource"]; got != `"cedar"` {
			t.Fatalf("ContainerImageSource = %s, want \"cedar\"", got)
		}
		if strings.Contains(ad["Requirements"], "HasFileTransferPluginMethods") {
			t.Errorf("Requirements = %s, want no plugin clause", ad["Requirements"])
		}
	})

	t.Run("an empty source still gets a clause", func(t *testing.T) {
		// `container_image = :` leaves the scheme empty. condor_submit
		// emits the clause anyway and writes no attribute, because it
		// builds the attribute by appending a comma only when it already
		// has something.
		ad := adForBehavior(t, b, "universe = container\ncontainer_image = :\nqueue\n")
		if got := ad["ContainerImageSource"]; got != `""` {
			t.Fatalf("ContainerImageSource = %s, want the empty string", got)
		}
		if !strings.Contains(ad["Requirements"], clause("")) {
			t.Errorf("Requirements = %s, want it to carry %s", ad["Requirements"], clause(""))
		}
		if got, ok := ad["WantTransferPluginMethods"]; ok {
			t.Errorf("WantTransferPluginMethods = %s, want it absent", got)
		}
	})

	t.Run("before the behavior landed", func(t *testing.T) {
		ad := adForBehavior(t, SubmitBehavior{}, "universe = container\ncontainer_image = foo:bar.sif\nqueue\n")
		if strings.Contains(ad["Requirements"], clause("foo")) {
			t.Errorf("Requirements = %s, want no clause for the container source", ad["Requirements"])
		}
		if got, ok := ad["WantTransferPluginMethods"]; ok {
			t.Errorf("WantTransferPluginMethods = %s, want it absent", got)
		}
	})
}
