package htcondor

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/PelicanPlatform/classad/classad"
)

// TestGetInputFilesFromJobAd covers the per-job file-set extraction
// shared by SpoolJobFilesFromFS and SpoolJobFilesFromTar. The bug fix
// in this commit makes both spool entry points use this helper, so its
// behavior governs whether minimal jobs (executable only, no
// transfer_input_files) can spool.
func TestGetInputFilesFromJobAd(t *testing.T) {
	tests := []struct {
		name string
		// setup mutates a fresh ad to the desired shape.
		setup func(ad *classad.ClassAd)
		want  []string
	}{
		{
			// The bug we're fixing: a job whose only transferable file
			// is its executable. Pre-fix this returned an empty set,
			// which SpoolJobFilesFromFS treated as "missing
			// TransferInput" and rejected.
			name: "executable only, no transfer_input_files",
			setup: func(ad *classad.ClassAd) {
				_ = ad.Set("Cmd", "interactive-watchdog.sh")
				// TransferExecutable defaults to true; leave it unset
				// to verify the default path explicitly.
			},
			want: []string{"interactive-watchdog.sh"},
		},
		{
			name: "transfer_input_files plus executable",
			setup: func(ad *classad.ClassAd) {
				_ = ad.Set("Cmd", "/usr/bin/jupyter")
				_ = ad.Set("TransferInput", "htcondor-jupyter-helper,jupyter-token")
				_ = ad.Set("TransferExecutable", true)
			},
			want: []string{"htcondor-jupyter-helper", "jupyter", "jupyter-token"},
		},
		{
			name: "transfer_executable=false, only TransferInput",
			setup: func(ad *classad.ClassAd) {
				_ = ad.Set("Cmd", "/bin/bash") // should be excluded
				_ = ad.Set("TransferInput", "input.txt")
				_ = ad.Set("TransferExecutable", false)
			},
			want: []string{"input.txt"},
		},
		{
			// Defensive: an ad with neither inputs nor a Cmd can't
			// spool anything. The helper returns an empty set; the
			// FS-path validation upstream is what surfaces the error.
			name: "neither inputs nor executable yields empty set",
			setup: func(ad *classad.ClassAd) {
				_ = ad.Set("TransferExecutable", false)
			},
			want: nil,
		},
		{
			// transfer_executable=true with no Cmd is also an empty
			// set. Real submit files always set Cmd, but the helper
			// shouldn't panic if it isn't.
			name: "transfer_executable=true but no Cmd",
			setup: func(ad *classad.ClassAd) {
				// nothing
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad := classad.New()
			tt.setup(ad)
			got := keysSorted(getInputFilesFromJobAd(ad))
			if !equalStringSlices(got, tt.want) {
				t.Errorf("getInputFilesFromJobAd = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSpoolJobFilesFromFS_ValidationRejectsEmpty exercises the
// SpoolJobFilesFromFS pre-flight validation: an ad with no inputs and
// no executable to transfer must error out *before* any network I/O.
// Uses a deliberately-bogus schedd address; if the validation lets the
// ad through, the test would fail with a connection error instead.
func TestSpoolJobFilesFromFS_ValidationRejectsEmpty(t *testing.T) {
	ad := classad.New()
	_ = ad.Set("ClusterId", int64(42))
	_ = ad.Set("ProcId", int64(0))
	_ = ad.Set("TransferExecutable", false)
	// No TransferInput, no Cmd, no transferable executable → empty file set.

	schedd := NewSchedd("test", "127.0.0.1:1") // unreachable on purpose

	err := schedd.SpoolJobFilesFromFS(
		context.Background(),
		[]*classad.ClassAd{ad},
		fstest.MapFS{},
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// "no files to spool" is the new error string from the fixed
	// validation. The pre-fix wording ("missing TransferInput") would
	// also indicate a parse-stage rejection, but since we own this
	// path now we should pin the specific message so a future change
	// that drops the validation surfaces here.
	if !strings.Contains(err.Error(), "no files to spool") {
		t.Errorf("expected error mentioning %q, got: %v", "no files to spool", err)
	}
	if strings.Contains(err.Error(), "connect") {
		t.Errorf("validation should reject before network I/O; got connection error: %v", err)
	}
}

// TestSpoolJobFilesFromFS_AcceptsExecutableOnly is the regression test
// for the "interactive terminal" submission path. Pre-fix this would
// fail with `missing TransferInput attribute` because the helper only
// has the executable to transfer. Post-fix it must get past parsing
// and *fail at the network step* (since we use an unreachable address).
func TestSpoolJobFilesFromFS_AcceptsExecutableOnly(t *testing.T) {
	ad := classad.New()
	_ = ad.Set("ClusterId", int64(42))
	_ = ad.Set("ProcId", int64(0))
	_ = ad.Set("Cmd", "interactive-watchdog.sh")
	// TransferExecutable defaults to true.
	// No TransferInput.

	schedd := NewSchedd("test", "127.0.0.1:1") // unreachable on purpose

	err := schedd.SpoolJobFilesFromFS(
		context.Background(),
		[]*classad.ClassAd{ad},
		fstest.MapFS{
			"interactive-watchdog.sh": &fstest.MapFile{
				Data: []byte("#!/bin/sh\nexit 0\n"),
				Mode: 0o755,
			},
		},
	)
	if err == nil {
		t.Fatal("expected an error from the unreachable schedd, got nil")
	}
	// Must NOT be the parse-stage "no files to spool" / "missing
	// TransferInput" error — that would mean the bug is still here.
	if strings.Contains(err.Error(), "no files to spool") ||
		strings.Contains(err.Error(), "missing TransferInput") {
		t.Errorf("regression: parse-stage rejected an executable-only ad: %v", err)
	}
}

// equalStringSlices is a small helper since the helper-returned map
// has nondeterministic iteration order; we sort and compare.
func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func keysSorted(m map[string]bool) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// `sort` is package-level imported by schedd_transfer.go; the test
	// file gets it via that package (not transitively re-exported), so
	// import it here separately.
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	// tiny insertion sort to avoid importing "sort" just for tests
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
