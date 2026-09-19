package htcondor

import (
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// The expected values below were taken from real condor_submit -dry-run on
// identical submit files, not from this implementation. That matters: the
// bug these tests cover was an implementation that disagreed with condor
// while looking perfectly reasonable on its own terms.
//
// Base units differ per attribute -- RequestMemory is MiB, RequestDisk is
// KiB -- so the same literal means different numbers depending on where it
// appears. Every case below states which base it is exercising.

func TestParseSizeWithUnits(t *testing.T) {
	tests := []struct {
		name string
		in   string
		base int64
		want int64
		ok   bool
	}{
		// No suffix: already in the attribute's base unit.
		{"bare number is base units (MiB)", "4096", unitMiB, 4096, true},
		{"bare number is base units (KiB)", "1024", unitKiB, 1024, true},
		{"zero", "0", unitMiB, 0, true},

		// The bug: a suffix must scale, not be discarded.
		{"GB into MiB", "4GB", unitMiB, 4096, true},
		{"GB into KiB", "10GB", unitKiB, 10485760, true},
		{"G without B", "2G", unitMiB, 2048, true},
		{"M into KiB", "512M", unitKiB, 524288, true},
		{"T into MiB", "1T", unitMiB, 1048576, true},

		// Case insensitivity and the optional trailing b/B.
		{"lowercase gb", "4gb", unitMiB, 4096, true},
		{"lowercase mb into KiB", "2mb", unitKiB, 2048, true},
		{"mixed case Gb", "4Gb", unitMiB, 4096, true},

		// Whitespace between number and suffix is allowed.
		{"space before suffix", "100 MB", unitMiB, 100, true},
		{"leading whitespace", "  8G", unitMiB, 8192, true},

		// Fractions, with the result rounded UP to whole base units.
		{"fraction 2.5G", "2.5G", unitMiB, 2560, true},
		{"fraction 1.5T into KiB", "1.5T", unitKiB, 1610612736, true},

		// Ceiling: 1500 KiB is 1.43 MiB, which must round up to 2, not
		// truncate to 1. Truncating would under-request.
		{"ceiling rounds up", "1500k", unitMiB, 2, true},
		{"one byte over rounds up", "1025k", unitMiB, 2, true},
		{"exact multiple does not round up", "2048k", unitMiB, 2, true},

		// Not sizes. The caller stores these as expressions instead;
		// what matters here is that they are reported as non-sizes
		// rather than silently yielding a number.
		{"expression", "ifThenElse(X > 1, 2048, 1024)", unitMiB, 0, false},
		{"attribute reference", "MY.VM_Memory", unitMiB, 0, false},
		{"arithmetic", "512 * 4", unitMiB, 0, false},
		{"empty", "", unitMiB, 0, false},
		{"suffix only", "GB", unitMiB, 0, false},
		{"bare B is not a multiplier", "1024B", unitMiB, 0, false},
		{"trailing junk", "4GBB", unitMiB, 0, false},
		{"unknown suffix", "4X", unitMiB, 0, false},
		{"not a number", "lots", unitMiB, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSizeWithUnits(tc.in, tc.base)
			if ok != tc.ok {
				t.Fatalf("parseSizeWithUnits(%q, %d) ok = %v, want %v (got value %d)",
					tc.in, tc.base, ok, tc.ok, got)
			}
			if ok && got != tc.want {
				t.Errorf("parseSizeWithUnits(%q, %d) = %d, want %d",
					tc.in, tc.base, got, tc.want)
			}
		})
	}
}

// TestSubmitSizeUnitsEndToEnd drives the whole submit path, because the
// unit bug was invisible at that level: the job ad simply carried a small
// number and nothing reported an error.
func TestSubmitSizeUnitsEndToEnd(t *testing.T) {
	tests := []struct {
		name       string
		submit     string
		wantMemory int64 // RequestMemory, MiB
		wantDisk   int64 // RequestDisk, KiB
	}{
		{
			name:       "suffixed values scale",
			submit:     "request_memory = 4GB\nrequest_disk = 10GB\n",
			wantMemory: 4096,
			wantDisk:   10485760,
		},
		{
			name:       "bare values are base units",
			submit:     "request_memory = 4096\nrequest_disk = 1024\n",
			wantMemory: 4096,
			wantDisk:   1024,
		},
		{
			name:       "the request that started this: 16GB/30GB",
			submit:     "request_memory = 16GB\nrequest_disk = 30GB\n",
			wantMemory: 16384,
			wantDisk:   31457280,
		},
		{
			name:       "fractional",
			submit:     "request_memory = 2.5G\nrequest_disk = 512M\n",
			wantMemory: 2560,
			wantDisk:   524288,
		},
		{
			name:       "defaults when unspecified",
			submit:     "",
			wantMemory: 128,
			wantDisk:   1024,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ad := mustJobAd(t, "universe = vanilla\nexecutable = /bin/echo\n"+tc.submit)

			if got, ok := ad.EvaluateAttrInt("RequestMemory"); !ok || got != tc.wantMemory {
				t.Errorf("RequestMemory = %d (ok=%v), want %d", got, ok, tc.wantMemory)
			}
			if got, ok := ad.EvaluateAttrInt("RequestDisk"); !ok || got != tc.wantDisk {
				t.Errorf("RequestDisk = %d (ok=%v), want %d", got, ok, tc.wantDisk)
			}
		})
	}
}

// TestSubmitSizeUnitsOtherAttributes covers the rest of the size-valued
// commands, which shared the same parser and so shared the same bug.
func TestSubmitSizeUnitsOtherAttributes(t *testing.T) {
	ad := mustJobAd(t, `
universe = vanilla
executable = /bin/echo
request_gpu_memory = 8GB
image_size = 2MB
executable_size = 512k
disk_usage = 1GB
`)

	for _, tc := range []struct {
		attr string
		want int64
	}{
		{"RequestGpuMemory", 8192}, // MiB base
		{"ImageSize", 2048},        // KiB base
		{"ExecutableSize", 512},    // KiB base
		{"DiskUsage", 1048576},     // KiB base
	} {
		if got, ok := ad.EvaluateAttrInt(tc.attr); !ok || got != tc.want {
			t.Errorf("%s = %d (ok=%v), want %d", tc.attr, got, ok, tc.want)
		}
	}
}

// TestSubmitSizeExpressionPreserved covers the second, quieter defect: an
// expression-valued request used to be dropped on the floor, leaving the
// hardcoded default with no error. condor_submit stores the expression.
func TestSubmitSizeExpressionPreserved(t *testing.T) {
	ad := mustJobAd(t, `
universe = vanilla
executable = /bin/echo
request_memory = 512 * 4
`)

	got, ok := ad.EvaluateAttrInt("RequestMemory")
	if !ok {
		t.Fatal("RequestMemory did not evaluate to an integer")
	}
	if got == 128 {
		t.Fatal("RequestMemory is the default 128: the expression was silently dropped")
	}
	if got != 2048 {
		t.Errorf("RequestMemory = %d, want 2048 (the expression evaluated)", got)
	}
}

// A value that is neither a size nor a parseable expression must be
// reported, not quietly replaced by the default.
func TestSubmitSizeInvalidIsReported(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader(`
universe = vanilla
executable = /bin/echo
request_memory = ((
`))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}

	_, err = sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, map[string]string{})
	if err == nil {
		t.Fatal("expected an error for an unparseable request_memory, got none")
	}
	if !strings.Contains(err.Error(), "RequestMemory") {
		t.Errorf("error should name the attribute, got: %v", err)
	}
}

// TestSubmitCountAttributes covers request_cpus / request_gpus. They take
// no units, but they are expression-valued in condor, and the old
// fmt.Sscanf("%d") parse quietly accepted a prefix of one: "2.5" became 2
// and "2 * 2" became 2.
//
// Stored forms here were checked against condor_submit -dry-run, which
// keeps "2 * 2" and "2.5" verbatim rather than folding them.
func TestSubmitCountAttributes(t *testing.T) {
	t.Run("plain integer", func(t *testing.T) {
		ad := mustJobAd(t, "universe = vanilla\nexecutable = /bin/echo\nrequest_cpus = 4\n")
		if got, ok := ad.EvaluateAttrInt("RequestCpus"); !ok || got != 4 {
			t.Errorf("RequestCpus = %d (ok=%v), want 4", got, ok)
		}
	})

	t.Run("default when unspecified", func(t *testing.T) {
		ad := mustJobAd(t, "universe = vanilla\nexecutable = /bin/echo\n")
		if got, ok := ad.EvaluateAttrInt("RequestCpus"); !ok || got != 1 {
			t.Errorf("RequestCpus = %d (ok=%v), want 1", got, ok)
		}
	})

	// The old parse truncated this to 2. It must not silently become a
	// different count.
	t.Run("real is not truncated to an int", func(t *testing.T) {
		ad := mustJobAd(t, "universe = vanilla\nexecutable = /bin/echo\nrequest_cpus = 2.5\n")
		if got, ok := ad.EvaluateAttrInt("RequestCpus"); ok && got == 2 {
			t.Fatal("RequestCpus truncated to 2: the fractional part was silently dropped")
		}
		if got, ok := ad.EvaluateAttrReal("RequestCpus"); !ok || got != 2.5 {
			t.Errorf("RequestCpus real = %v (ok=%v), want 2.5", got, ok)
		}
	})

	// The old parse also truncated this to 2, losing the multiplication.
	t.Run("arithmetic expression is preserved", func(t *testing.T) {
		ad := mustJobAd(t, "universe = vanilla\nexecutable = /bin/echo\nrequest_cpus = 2 * 2\n")
		got, ok := ad.EvaluateAttrInt("RequestCpus")
		if !ok {
			t.Fatal("RequestCpus did not evaluate to an integer")
		}
		if got == 2 {
			t.Fatal("RequestCpus = 2: the expression was truncated at the first token")
		}
		if got != 4 {
			t.Errorf("RequestCpus = %d, want 4", got)
		}
	})

	t.Run("gpus take the same path", func(t *testing.T) {
		ad := mustJobAd(t, "universe = vanilla\nexecutable = /bin/echo\nrequest_gpus = 1 + 1\n")
		got, ok := ad.EvaluateAttrInt("RequestGpus")
		if !ok {
			t.Fatal("RequestGpus did not evaluate to an integer")
		}
		if got != 2 {
			t.Errorf("RequestGpus = %d, want 2", got)
		}
	})

	t.Run("unparseable is reported", func(t *testing.T) {
		sf, err := ParseSubmitFile(strings.NewReader(
			"universe = vanilla\nexecutable = /bin/echo\nrequest_cpus = ((\n"))
		if err != nil {
			t.Fatalf("ParseSubmitFile: %v", err)
		}
		if _, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, map[string]string{}); err == nil {
			t.Fatal("expected an error for an unparseable request_cpus, got none")
		}
	})
}

func mustJobAd(t *testing.T, submit string) *classad.ClassAd {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, map[string]string{})
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	if ad == nil {
		t.Fatal("nil job ad")
	}
	return ad
}
