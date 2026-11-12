//go:build libcondor_utils

package fuzzsubmit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExecNamesDirectory pins the guard that keeps the oracle away from a
// filesystem walk.
//
// condor_submit sizes a directory named as the executable by walking it, so
// `executable = /` never returns inside the cgo call and takes the fuzz worker
// with it. The guard is what the fuzz targets rely on to stay bounded, and it
// has no other test: the shape that exercises it in anger is the one that
// hangs.
func TestExecNamesDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "exe")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	adsWithCmd := func(cmd string) Ads {
		return Ads{ByKey: map[AdKey]map[string]string{
			{Cluster: 1, Proc: 0}: {"Cmd": `"` + cmd + `"`},
		}}
	}

	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		{"a directory", dir, true},
		{"the root directory", "/", true},
		{"a regular file", file, false},
		{"a path that does not exist", filepath.Join(dir, "nope"), false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := execNamesDirectory(adsWithCmd(tc.cmd)); got != tc.want {
				t.Errorf("execNamesDirectory(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
		})
	}

	// A relative executable is resolved the way condor_submit resolves it,
	// against the working directory. A guard that only looked at the literal
	// value would let the walk through.
	t.Run("relative directory", func(t *testing.T) {
		wd, err := os.Getwd()
		if err != nil {
			t.Fatal(err)
		}
		rel, err := filepath.Rel(wd, dir)
		if err != nil {
			t.Skipf("no relative path from %s to %s", wd, dir)
		}
		if !execNamesDirectory(adsWithCmd(rel)) {
			t.Errorf("execNamesDirectory(%q) = false; a relative directory still walks", rel)
		}
	})

	// No Cmd at all must not be read as a directory.
	t.Run("no Cmd attribute", func(t *testing.T) {
		ads := Ads{ByKey: map[AdKey]map[string]string{{Cluster: 1, Proc: 0}: {"Universe": "5"}}}
		if execNamesDirectory(ads) {
			t.Error("execNamesDirectory = true for an ad with no Cmd")
		}
	})
}
