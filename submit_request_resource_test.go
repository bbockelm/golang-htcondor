package htcondor

import (
	"strings"
	"testing"
)

// request_<tag> is generic in HTCondor: SubmitHash::SetRequestResources
// walks the whole submit macro set, and every key starting "request_"
// that has no setter of its own becomes the job attribute "Request"
// plus the rest of the key, verbatim, holding the value as a ClassAd
// expression. That is how a job asks for a resource the pool defines
// itself, and the expected values below are what libcondor_utils 26.2.0
// produced for the same submit files through the differential harness
// in fuzz/submit.

// attrNamed returns the attribute as the ad spells it, so a test can
// tell RequestLicenses from Requestlicenses -- HTCondor keeps the tag's
// own capitalization and does not title-case it.
func attrNamed(t *testing.T, submit, attr string) (string, bool) {
	t.Helper()
	ad := mustJobAd(t, submit)
	for _, name := range ad.GetAttributes() {
		if name == attr {
			expr, ok := ad.Lookup(name)
			if !ok {
				t.Fatalf("%s is listed but does not look up", name)
			}
			return expr.String(), true
		}
	}
	return "", false
}

func TestSubmitGenericResourceRequest(t *testing.T) {
	const preamble = "universe = vanilla\nexecutable = /bin/echo\n"

	for _, tc := range []struct {
		name    string
		command string
		attr    string
		// want is the attribute's value evaluated as an integer;
		// wantString is used instead when the request is a string.
		want       int64
		wantString string
	}{
		{
			name:    "uppercase tag keeps its case",
			command: "request_A0 = 3",
			attr:    "RequestA0",
			want:    3,
		},
		{
			name:    "lowercase tag is not title-cased",
			command: "request_licenses = 4",
			attr:    "Requestlicenses",
			want:    4,
		},
		{
			name:    "underscores inside the tag are kept",
			command: "request_my_thing = 5",
			attr:    "Requestmy_thing",
			want:    5,
		},
		{
			name:    "the prefix itself is matched case-insensitively",
			command: "Request_Foo = 5",
			attr:    "RequestFoo",
			want:    5,
		},
		{
			name:    "the value is an expression, not a count",
			command: "request_slots = 2*2",
			attr:    "Requestslots",
			want:    4,
		},
		{
			name:       "a string request stays a string",
			command:    `request_bandwidth = "high"`,
			attr:       "Requestbandwidth",
			wantString: "high",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := mustJobAd(t, preamble+tc.command+"\n")
			if _, ok := attrNamed(t, preamble+tc.command+"\n", tc.attr); !ok {
				t.Fatalf("%s is missing; ad has %v", tc.attr, ad.GetAttributes())
			}
			switch {
			case tc.wantString != "":
				if got, ok := ad.EvaluateAttrString(tc.attr); !ok || got != tc.wantString {
					t.Errorf("%s = %q (ok=%v), want %q", tc.attr, got, ok, tc.wantString)
				}
			default:
				if got, ok := ad.EvaluateAttrInt(tc.attr); !ok || got != tc.want {
					t.Errorf("%s = %d (ok=%v), want %d", tc.attr, got, ok, tc.want)
				}
			}
		})
	}
}

// TestSubmitGenericResourceRequestUndefined: "undefined" is stored as
// the literal. For request_cpus and the other three it means the
// opposite -- leave the attribute out -- which is a property of their
// own setters, not of the request_ prefix.
func TestSubmitGenericResourceRequestUndefined(t *testing.T) {
	got, ok := attrNamed(t, "universe = vanilla\nexecutable = /bin/echo\nrequest_colors = undefined\n", "Requestcolors")
	if !ok {
		t.Fatal("Requestcolors is missing")
	}
	if got != "undefined" {
		t.Errorf("Requestcolors = %s, want undefined", got)
	}
}

// TestSubmitGenericResourceRequestSkipped covers the keys that look like
// resource requests and are not. C++ sets no attribute for any of them:
// a tag has to be at least two characters and may not start with an
// underscore, the singular spellings earn a warning instead of a "Cpu"
// resource, and the two gpu-memory keys are listed as disallowed
// keywords.
func TestSubmitGenericResourceRequestSkipped(t *testing.T) {
	const preamble = "universe = vanilla\nexecutable = /bin/echo\n"

	for _, tc := range []struct {
		command string
		attr    string
	}{
		{"request_f = 5", "Requestf"},
		{"request__foo = 6", "Request_foo"},
		{"request_1 = 7", "Request1"},
		{"request_cpu = 2", "Requestcpu"},
		{"request_gpu = 2", "Requestgpu"},
		{"request_gpus = 1\nrequest_gpus_memory = 100", "Requestgpus_memory"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			if got, ok := attrNamed(t, preamble+tc.command+"\n", tc.attr); ok {
				t.Errorf("%s = %s, want no such attribute", tc.attr, got)
			}
		})
	}
}

// TestSubmitGenericResourceRequestLeavesSpecialsAlone checks the generic
// path does not take over the four requests that have their own
// handling, which scale units and evaluate rather than storing an
// expression.
func TestSubmitGenericResourceRequestLeavesSpecialsAlone(t *testing.T) {
	ad := mustJobAd(t, `
universe = vanilla
executable = /bin/echo
request_cpus = 2
request_memory = 4GB
request_disk = 10GB
request_gpus = 3
`)
	for _, tc := range []struct {
		attr string
		want int64
	}{
		{"RequestCpus", 2},
		{"RequestMemory", 4096},   // MiB
		{"RequestDisk", 10485760}, // KiB
		{"RequestGpus", 3},
	} {
		if got, ok := ad.EvaluateAttrInt(tc.attr); !ok || got != tc.want {
			t.Errorf("%s = %d (ok=%v), want %d", tc.attr, got, ok, tc.want)
		}
	}
	// request_memory = 4GB would be the unparsable expression "4GB" if
	// the generic path had claimed it.
	for _, name := range ad.GetAttributes() {
		if name == "Requestmemory" || name == "Requestcpus" || name == "Requestdisk" || name == "Requestgpus" {
			t.Errorf("generic path also produced %s", name)
		}
	}
}

// TestSubmitGenericResourceRequestCustomAttributeWins: +Requestfoo is
// applied after the request_ commands in C++ (SetForcedSubmitAttrs runs
// after SetRequestResources), so it overwrites the value.
func TestSubmitGenericResourceRequestCustomAttributeWins(t *testing.T) {
	ad := mustJobAd(t, "universe = vanilla\nexecutable = /bin/echo\n+Requestfoo = 9\nrequest_foo = 3\n")
	if got, ok := ad.EvaluateAttrInt("Requestfoo"); !ok || got != 9 {
		t.Errorf("Requestfoo = %d (ok=%v), want 9", got, ok)
	}
}

// TestSubmitGenericResourceRequestFirstSpellingWins: HTCondor's macro
// set keeps the name it already holds and replaces only the value, so
// the attribute is spelled from the first occurrence and carries the
// last value.
func TestSubmitGenericResourceRequestFirstSpellingWins(t *testing.T) {
	const submit = "universe = vanilla\nexecutable = /bin/echo\nrequest_Foo = 1\nrequest_FOO = 2\n"
	got, ok := attrNamed(t, submit, "RequestFoo")
	if !ok {
		t.Fatalf("RequestFoo is missing; ad has %v", mustJobAd(t, submit).GetAttributes())
	}
	if got != "2" {
		t.Errorf("RequestFoo = %s, want 2", got)
	}
	if _, ok := attrNamed(t, submit, "RequestFOO"); ok {
		t.Error("RequestFOO: the second spelling should not have created its own attribute")
	}
}

// TestSubmitGenericResourceRequestInvalidExpression: the value is stored
// as an expression with no unit scaling, so "10GB" is not a 10 GB
// request, it is a parse error -- condor_submit rejects the file.
func TestSubmitGenericResourceRequestInvalidExpression(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("universe = vanilla\nexecutable = /bin/echo\nrequest_foo = 10GB\n"))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	if _, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, map[string]string{}); err == nil {
		t.Fatal("request_foo = 10GB was accepted; want a ClassAd expression error")
	} else if !strings.Contains(err.Error(), "request_foo") {
		t.Errorf("error does not name the command: %v", err)
	}
}
