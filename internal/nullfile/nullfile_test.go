package nullfile

import (
	"runtime"
	"testing"
)

func TestIs(t *testing.T) {
	for _, tc := range []struct {
		name string
		goos string
		want bool
	}{
		{"/dev/null", "linux", true},
		{"/dev/null", "darwin", true},
		{"/dev/null", "windows", true},

		// The empty string is not the null file. nullfile.cpp matches
		// "/dev/null" and nothing else; treating "" as the null file
		// silently turns "the job ad said nothing" into "the job ad
		// said discard it".
		{"", "linux", false},
		{"", "windows", false},

		// Not the null file, however much they look like it.
		{"/dev/nulll", "linux", false},
		{"dev/null", "linux", false},
		{"/dev/null ", "linux", false},
		{"/DEV/NULL", "linux", false},
		{"/private/dev/null", "linux", false},
		{"null", "linux", false},
		{"NUL", "linux", false},
		{"nul", "darwin", false},

		// NUL is the null file only on Windows, where the match is
		// case-insensitive.
		{"NUL", "windows", true},
		{"nul", "windows", true},
		{"Nul", "windows", true},
		{"NUL:", "windows", false},
		{"NULL", "windows", false},
	} {
		t.Run(tc.goos+"/"+tc.name, func(t *testing.T) {
			if got := is(tc.name, tc.goos); got != tc.want {
				t.Errorf("is(%q, %q) = %v, want %v", tc.name, tc.goos, got, tc.want)
			}
		})
	}
}

// TestIsUsesRunningPlatform keeps the exported entry point wired to
// runtime.GOOS rather than to a hardcoded arm.
func TestIsUsesRunningPlatform(t *testing.T) {
	if got, want := Is("/dev/null"), true; got != want {
		t.Errorf("Is(%q) = %v, want %v", "/dev/null", got, want)
	}
	if got, want := Is("NUL"), runtime.GOOS == "windows"; got != want {
		t.Errorf("Is(%q) = %v, want %v on %s", "NUL", got, want, runtime.GOOS)
	}
}
