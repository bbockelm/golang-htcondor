package htcondor

import (
	"reflect"
	"testing"
)

func TestParseOutputRemaps(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []OutputRemap
	}{
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "whitespace only",
			input:    "   ",
			expected: nil,
		},
		{
			name:  "simple single remap",
			input: "output.txt=renamed.txt",
			expected: []OutputRemap{
				{Source: "output.txt", Destination: "renamed.txt", IsURL: false},
			},
		},
		{
			name:  "single remap with spaces",
			input: "  output.txt  =  renamed.txt  ",
			expected: []OutputRemap{
				{Source: "output.txt", Destination: "renamed.txt", IsURL: false},
			},
		},
		{
			name:  "multiple remaps",
			input: "file1.txt=new1.txt;file2.dat=new2.dat",
			expected: []OutputRemap{
				{Source: "file1.txt", Destination: "new1.txt", IsURL: false},
				{Source: "file2.dat", Destination: "new2.dat", IsURL: false},
			},
		},
		{
			name:  "multiple remaps with spaces",
			input: "  file1.txt = new1.txt  ;  file2.dat = new2.dat  ",
			expected: []OutputRemap{
				{Source: "file1.txt", Destination: "new1.txt", IsURL: false},
				{Source: "file2.dat", Destination: "new2.dat", IsURL: false},
			},
		},
		{
			name:  "remap to URL - s3",
			input: "output.txt=s3://bucket/path/file.txt",
			expected: []OutputRemap{
				{Source: "output.txt", Destination: "s3://bucket/path/file.txt", IsURL: true},
			},
		},
		{
			name:  "remap to URL - https",
			input: "data.csv=https://example.com/upload/data.csv",
			expected: []OutputRemap{
				{Source: "data.csv", Destination: "https://example.com/upload/data.csv", IsURL: true},
			},
		},
		{
			name:  "remap to URL - osdf",
			input: "result.root=osdf:///path/to/result.root",
			expected: []OutputRemap{
				{Source: "result.root", Destination: "osdf:///path/to/result.root", IsURL: true},
			},
		},
		{
			name:  "mixed local and URL destinations",
			input: "local.txt=renamed.txt;remote.dat=s3://bucket/remote.dat",
			expected: []OutputRemap{
				{Source: "local.txt", Destination: "renamed.txt", IsURL: false},
				{Source: "remote.dat", Destination: "s3://bucket/remote.dat", IsURL: true},
			},
		},
		{
			name:  "escaped semicolon in filename",
			input: `file\;1.txt=renamed.txt`,
			expected: []OutputRemap{
				{Source: "file;1.txt", Destination: "renamed.txt", IsURL: false},
			},
		},
		{
			name:  "escaped equals in filename",
			input: `key\=value.txt=renamed.txt`,
			expected: []OutputRemap{
				{Source: "key=value.txt", Destination: "renamed.txt", IsURL: false},
			},
		},
		{
			name:  "escaped semicolon in destination",
			input: `output.txt=path\;with\;semicolons.txt`,
			expected: []OutputRemap{
				{Source: "output.txt", Destination: "path;with;semicolons.txt", IsURL: false},
			},
		},
		{
			name:  "multiple remaps with escapes",
			input: `file\;1.txt=new1.txt;file\=2.txt=new2.txt`,
			expected: []OutputRemap{
				{Source: "file;1.txt", Destination: "new1.txt", IsURL: false},
				{Source: "file=2.txt", Destination: "new2.txt", IsURL: false},
			},
		},
		{
			name:  "remap to subdirectory",
			input: "output.txt=results/output.txt",
			expected: []OutputRemap{
				{Source: "output.txt", Destination: "results/output.txt", IsURL: false},
			},
		},
		{
			name:  "empty pairs are skipped",
			input: ";;a.txt=b.txt;;",
			expected: []OutputRemap{
				{Source: "a.txt", Destination: "b.txt", IsURL: false},
			},
		},
		{
			name:     "missing equals is skipped",
			input:    "no_equals",
			expected: nil,
		},
		{
			name:     "empty source is skipped",
			input:    "=dest.txt",
			expected: nil,
		},
		{
			name:     "empty destination is skipped",
			input:    "src.txt=",
			expected: nil,
		},
		{
			name:  "backslash not followed by special char",
			input: `path\with\backslash.txt=new.txt`,
			expected: []OutputRemap{
				{Source: `pathwithbackslash.txt`, Destination: "new.txt", IsURL: false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOutputRemaps(tt.input)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("parseOutputRemaps(%q) = %+v, want %+v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		path     string
		expected bool
	}{
		// Valid URLs
		{"http://example.com", true},
		{"https://example.com/path", true},
		{"s3://bucket/key", true},
		{"gs://bucket/object", true},
		{"file:///path/to/file", true},
		{"osdf:///path/to/file", true},
		{"ftp://server/file", true},
		{"s3+http://bucket/key", true},

		// Not URLs
		{"", false},
		{"/path/to/file", false},
		{"relative/path", false},
		{"file.txt", false},
		{"./file.txt", false},
		{"../file.txt", false},
		{"C:\\Windows\\file.txt", false},

		// Edge cases
		{"://missing-scheme", false},
		{"://", false},
		{"scheme://", true},          // Valid scheme with empty path
		{"a://valid", true},          // Single letter scheme
		{"123://invalid", false},     // Scheme can't start with number
		{"my-scheme://path", true},   // Scheme with hyphen
		{"my.scheme://path", true},   // Scheme with dot
		{"my+scheme://path", true},   // Scheme with plus
		{"bad scheme://path", false}, // Scheme with space (invalid)
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := isURL(tt.path)
			if result != tt.expected {
				t.Errorf("isURL(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestSplitWithEscape(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		delim    byte
		expected []string
	}{
		{
			name:     "simple split",
			input:    "a;b;c",
			delim:    ';',
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "no delimiter",
			input:    "abc",
			delim:    ';',
			expected: []string{"abc"},
		},
		{
			name:     "escaped delimiter",
			input:    `a\;b;c`,
			delim:    ';',
			expected: []string{`a\;b`, "c"},
		},
		{
			name:     "multiple escapes",
			input:    `a\;b\;c;d`,
			delim:    ';',
			expected: []string{`a\;b\;c`, "d"},
		},
		{
			name:     "escape at end",
			input:    `a;b\;`,
			delim:    ';',
			expected: []string{"a", `b\;`},
		},
		{
			name:     "empty string",
			input:    "",
			delim:    ';',
			expected: []string{""},
		},
		{
			name:     "just delimiter",
			input:    ";",
			delim:    ';',
			expected: []string{"", ""},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := splitWithEscape(tt.input, tt.delim)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("splitWithEscape(%q, %q) = %v, want %v", tt.input, tt.delim, result, tt.expected)
			}
		})
	}
}

func TestSplitFirstWithEscape(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		delim      byte
		wantBefore string
		wantAfter  string
		wantFound  bool
	}{
		{
			name:       "simple split",
			input:      "a=b",
			delim:      '=',
			wantBefore: "a",
			wantAfter:  "b",
			wantFound:  true,
		},
		{
			name:       "no delimiter",
			input:      "abc",
			delim:      '=',
			wantBefore: "abc",
			wantAfter:  "",
			wantFound:  false,
		},
		{
			name:       "escaped delimiter",
			input:      `a\=b=c`,
			delim:      '=',
			wantBefore: `a\=b`,
			wantAfter:  "c",
			wantFound:  true,
		},
		{
			name:       "multiple equals - split at first",
			input:      "a=b=c",
			delim:      '=',
			wantBefore: "a",
			wantAfter:  "b=c",
			wantFound:  true,
		},
		{
			name:       "empty before",
			input:      "=value",
			delim:      '=',
			wantBefore: "",
			wantAfter:  "value",
			wantFound:  true,
		},
		{
			name:       "empty after",
			input:      "key=",
			delim:      '=',
			wantBefore: "key",
			wantAfter:  "",
			wantFound:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, after, found := splitFirstWithEscape(tt.input, tt.delim)
			if before != tt.wantBefore || after != tt.wantAfter || found != tt.wantFound {
				t.Errorf("splitFirstWithEscape(%q, %q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.input, tt.delim, before, after, found, tt.wantBefore, tt.wantAfter, tt.wantFound)
			}
		})
	}
}

func TestUnescapeRemapString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{`\;`, ";"},
		{`\=`, "="},
		{`a\;b\=c`, "a;b=c"},
		{`\\`, `\`}, // Double backslash becomes single
		{`path\\file`, `path\file`},
		{"no escapes", "no escapes"},
		{`trailing\`, `trailing\`}, // Trailing backslash alone is kept (nothing to escape)
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := unescapeRemapString(tt.input)
			if result != tt.expected {
				t.Errorf("unescapeRemapString(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestBuildRemapLookup(t *testing.T) {
	remaps := []OutputRemap{
		{Source: "file1.txt", Destination: "new1.txt", IsURL: false},
		{Source: "file2.txt", Destination: "s3://bucket/file2.txt", IsURL: true},
	}

	lookup := buildRemapLookup(remaps)

	// Check that both remaps are in the lookup
	if len(lookup) != 2 {
		t.Errorf("buildRemapLookup returned %d entries, want 2", len(lookup))
	}

	// Check file1.txt
	remap1, found := lookup["file1.txt"]
	if !found {
		t.Error("file1.txt not found in lookup")
	} else {
		if remap1.Destination != "new1.txt" {
			t.Errorf("file1.txt destination = %q, want %q", remap1.Destination, "new1.txt")
		}
		if remap1.IsURL {
			t.Error("file1.txt should not be a URL")
		}
	}

	// Check file2.txt
	remap2, found := lookup["file2.txt"]
	if !found {
		t.Error("file2.txt not found in lookup")
	} else {
		if remap2.Destination != "s3://bucket/file2.txt" {
			t.Errorf("file2.txt destination = %q, want %q", remap2.Destination, "s3://bucket/file2.txt")
		}
		if !remap2.IsURL {
			t.Error("file2.txt should be a URL")
		}
	}
}

func TestApplyOutputRemap(t *testing.T) {
	tests := []struct {
		name      string
		fileName  string
		remaps    map[string]OutputRemap
		wantPath  string
		wantFound bool
		wantIsURL bool
	}{
		{
			name:      "no remaps",
			fileName:  "file.txt",
			remaps:    map[string]OutputRemap{},
			wantPath:  "file.txt",
			wantFound: false,
			wantIsURL: false,
		},
		{
			name:     "exact match",
			fileName: "output.txt",
			remaps: map[string]OutputRemap{
				"output.txt": {Source: "output.txt", Destination: "renamed.txt", IsURL: false},
			},
			wantPath:  "renamed.txt",
			wantFound: true,
			wantIsURL: false,
		},
		{
			name:     "exact match with URL destination",
			fileName: "data.csv",
			remaps: map[string]OutputRemap{
				"data.csv": {Source: "data.csv", Destination: "s3://bucket/data.csv", IsURL: true},
			},
			wantPath:  "s3://bucket/data.csv",
			wantFound: true,
			wantIsURL: true,
		},
		{
			name:     "no match",
			fileName: "other.txt",
			remaps: map[string]OutputRemap{
				"output.txt": {Source: "output.txt", Destination: "renamed.txt", IsURL: false},
			},
			wantPath:  "other.txt",
			wantFound: false,
			wantIsURL: false,
		},
		// Prefix-based directory remapping tests
		{
			name:     "prefix match - simple directory remap",
			fileName: "result_files/foo.txt",
			remaps: map[string]OutputRemap{
				"result_files": {Source: "result_files", Destination: "files", IsURL: false},
			},
			wantPath:  "files/foo.txt",
			wantFound: true,
			wantIsURL: false,
		},
		{
			name:     "prefix match - nested subdirectory",
			fileName: "result_files/subdir/nested/data.csv",
			remaps: map[string]OutputRemap{
				"result_files": {Source: "result_files", Destination: "output", IsURL: false},
			},
			wantPath:  "output/subdir/nested/data.csv",
			wantFound: true,
			wantIsURL: false,
		},
		{
			name:     "prefix match - directory to URL",
			fileName: "uploads/image.png",
			remaps: map[string]OutputRemap{
				"uploads": {Source: "uploads", Destination: "s3://bucket/uploads", IsURL: true},
			},
			wantPath:  "s3://bucket/uploads/image.png",
			wantFound: true,
			wantIsURL: true,
		},
		{
			name:     "prefix match - multiple remaps, first match wins",
			fileName: "data/results/file.txt",
			remaps: map[string]OutputRemap{
				"data":         {Source: "data", Destination: "output_data", IsURL: false},
				"data/results": {Source: "data/results", Destination: "final_results", IsURL: false},
			},
			// Note: map iteration order is random, but both would match
			// The more specific one (data/results) should ideally match, but
			// since map order is undefined, we just check that one matches
			wantPath:  "", // Will be checked specially
			wantFound: true,
			wantIsURL: false,
		},
		{
			name:     "exact match takes priority over prefix",
			fileName: "result_files",
			remaps: map[string]OutputRemap{
				"result_files": {Source: "result_files", Destination: "renamed_dir", IsURL: false},
			},
			wantPath:  "renamed_dir",
			wantFound: true,
			wantIsURL: false,
		},
		{
			name:     "prefix not followed by slash - no match",
			fileName: "result_files_extra/foo.txt",
			remaps: map[string]OutputRemap{
				"result_files": {Source: "result_files", Destination: "files", IsURL: false},
			},
			wantPath:  "result_files_extra/foo.txt",
			wantFound: false,
			wantIsURL: false,
		},
		{
			name:     "partial filename match - no match",
			fileName: "my_result_files/foo.txt",
			remaps: map[string]OutputRemap{
				"result_files": {Source: "result_files", Destination: "files", IsURL: false},
			},
			wantPath:  "my_result_files/foo.txt",
			wantFound: false,
			wantIsURL: false,
		},
		{
			name:     "remap to subdirectory",
			fileName: "output/data.txt",
			remaps: map[string]OutputRemap{
				"output": {Source: "output", Destination: "results/final/output", IsURL: false},
			},
			wantPath:  "results/final/output/data.txt",
			wantFound: true,
			wantIsURL: false,
		},
		{
			name:     "deeply nested source directory",
			fileName: "a/b/c/d/file.txt",
			remaps: map[string]OutputRemap{
				"a/b/c": {Source: "a/b/c", Destination: "x/y", IsURL: false},
			},
			wantPath:  "x/y/d/file.txt",
			wantFound: true,
			wantIsURL: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotRemap, gotFound := applyOutputRemap(tt.fileName, tt.remaps)

			if gotFound != tt.wantFound {
				t.Errorf("applyOutputRemap(%q) found = %v, want %v", tt.fileName, gotFound, tt.wantFound)
				return
			}

			if !gotFound {
				if gotPath != tt.fileName {
					t.Errorf("applyOutputRemap(%q) path = %q, want %q (unchanged)", tt.fileName, gotPath, tt.fileName)
				}
				return
			}

			// For the multiple remaps test, just check that one valid remap was applied
			if tt.name == "prefix match - multiple remaps, first match wins" {
				if gotPath != "output_data/results/file.txt" && gotPath != "final_results/file.txt" {
					t.Errorf("applyOutputRemap(%q) path = %q, want one of the valid remaps", tt.fileName, gotPath)
				}
				return
			}

			if gotPath != tt.wantPath {
				t.Errorf("applyOutputRemap(%q) path = %q, want %q", tt.fileName, gotPath, tt.wantPath)
			}

			if gotRemap.IsURL != tt.wantIsURL {
				t.Errorf("applyOutputRemap(%q) isURL = %v, want %v", tt.fileName, gotRemap.IsURL, tt.wantIsURL)
			}
		})
	}
}
