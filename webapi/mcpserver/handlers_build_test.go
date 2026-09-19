package mcpserver

import (
	"strings"
	"testing"
)

func TestValidateBuildName(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{"py311.sif", true},
		{"my-image_v2.sif", true},
		{"", false},
		// A path component would publish somewhere other than the
		// staging base the operator configured.
		{"../escape.sif", false},
		{"sub/dir.sif", false},
		{`sub\dir.sif`, false},
		{".", false},
		{"..", false},
		// A leading dash is read as an option by the tools the name
		// reaches.
		{"-rf.sif", false},
		// apptainer writes .sif; anything else is a caller mistake we
		// can catch before spending a build slot on it.
		{"image.tar", false},
		{"image", false},
	} {
		err := validateBuildName(tc.name)
		if tc.ok && err != nil {
			t.Errorf("validateBuildName(%q) = %v, want nil", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("validateBuildName(%q) = nil, want an error", tc.name)
		}
	}
}

func TestBuildDestination(t *testing.T) {
	tests := []struct {
		name        string
		destination string
		stagingBase string
		image       string
		owner       string
		want        string
		wantErr     bool
	}{
		{
			name:        "explicit destination wins",
			destination: "osdf:///chtc/staging/b/alice/custom.sif",
			stagingBase: "osdf:///chtc/staging/b/alice",
			image:       "py311.sif",
			want:        "osdf:///chtc/staging/b/alice/custom.sif",
		},
		{
			name:        "staging base plus name",
			stagingBase: "osdf:///chtc/staging/b/alice",
			image:       "py311.sif",
			want:        "osdf:///chtc/staging/b/alice/py311.sif",
		},
		{
			name:        "trailing slash on the base is not doubled",
			stagingBase: "osdf:///chtc/staging/b/alice/",
			image:       "py311.sif",
			want:        "osdf:///chtc/staging/b/alice/py311.sif",
		},
		{
			name:    "no destination and no base is an error",
			image:   "py311.sif",
			wantErr: true,
		},
		{
			// A bare path would be written to the access point's
			// filesystem rather than published, which is not what
			// anyone means by "destination".
			name:        "destination without a scheme is rejected",
			destination: "/staging/b/alice/py311.sif",
			image:       "py311.sif",
			wantErr:     true,
		},
		{
			// CHTC's layout: /chtc/staging/<initial>/<netid>. A fixed
			// prefix cannot express it, which is why the template exists.
			name:        "per-user template",
			stagingBase: "osdf:///chtc/staging/{initial}/{user}",
			image:       "py311.sif",
			owner:       "bbockelm",
			want:        "osdf:///chtc/staging/b/bbockelm/py311.sif",
		},
		{
			name:        "user placeholder alone",
			stagingBase: "osdf:///site/builds/{user}",
			image:       "py311.sif",
			owner:       "alice",
			want:        "osdf:///site/builds/alice/py311.sif",
		},
		{
			name:        "initial is lowercased",
			stagingBase: "osdf:///chtc/staging/{initial}/{user}",
			image:       "x.sif",
			owner:       "Bbockelm",
			want:        "osdf:///chtc/staging/b/Bbockelm/x.sif",
		},
		{
			// An explicit destination bypasses the template entirely.
			name:        "explicit destination ignores the template",
			destination: "osdf:///elsewhere/x.sif",
			stagingBase: "osdf:///chtc/staging/{initial}/{user}",
			image:       "x.sif",
			owner:       "bbockelm",
			want:        "osdf:///elsewhere/x.sif",
		},
		{
			// Publishing to a path containing a literal "{user}" would
			// look like it worked.
			name:        "template with no identified caller is an error",
			stagingBase: "osdf:///chtc/staging/{initial}/{user}",
			image:       "x.sif",
			wantErr:     true,
		},
		{
			name:        "unknown placeholder is rejected",
			stagingBase: "osdf:///chtc/staging/{netid}",
			image:       "x.sif",
			owner:       "bbockelm",
			wantErr:     true,
		},
		{
			// Distinct from the case above: this one HAS a valid
			// placeholder, so it goes down the expansion path and is
			// caught only by the post-expansion check. Without this
			// case that check is dead code -- a mutation removing it
			// left every other test green.
			name:        "unknown placeholder alongside a valid one is rejected",
			stagingBase: "osdf:///chtc/staging/{user}/{netid}",
			image:       "x.sif",
			owner:       "bbockelm",
			wantErr:     true,
		},
		{
			// The owner comes from authentication, not the request, but
			// a separator in it would still walk out of the staging area.
			name:        "owner with a path separator is refused",
			stagingBase: "osdf:///chtc/staging/{user}",
			image:       "x.sif",
			owner:       "a/../../etc",
			wantErr:     true,
		},
		{
			name:        "owner with dot-dot is refused",
			stagingBase: "osdf:///chtc/staging/{user}",
			image:       "x.sif",
			owner:       "..",
			wantErr:     true,
		},
		{
			// A fixed base must not start requiring a caller.
			name:        "fixed base needs no caller",
			stagingBase: "osdf:///shared/builds",
			image:       "x.sif",
			want:        "osdf:///shared/builds/x.sif",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildDestination(tc.destination, tc.stagingBase, tc.image, tc.owner)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("buildDestination = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClampBuildResource(t *testing.T) {
	for _, tc := range []struct{ requested, def, max, want int }{
		{0, 8, 64, 8},    // unset takes the default
		{4, 8, 64, 4},    // an explicit request under the cap is honoured
		{128, 8, 64, 64}, // over the cap is lowered, not refused
		{128, 8, 0, 128}, // no cap configured means no ceiling
		{-1, 8, 64, 8},   // nonsense takes the default
	} {
		if got := clampBuildResource(tc.requested, tc.def, tc.max); got != tc.want {
			t.Errorf("clampBuildResource(%d, %d, %d) = %d, want %d",
				tc.requested, tc.def, tc.max, got, tc.want)
		}
	}
}

func TestBuildSubmitFile(t *testing.T) {
	cfg := buildSettings{
		extraSubmit:  "+IsBuildJob = True",
		requirements: "TARGET.HasApptainer",
		defCpus:      8,
		defMemoryMB:  16384,
		defDiskMB:    30720,
	}
	got := buildSubmitFile(cfg, "osdf:///chtc/staging/b/alice/py311.sif", 8, 16384, 30720)

	mustContain := []string{
		"executable              = build.sh",
		"transfer_input_files    = image.def",
		"request_cpus            = 8",
		// MiB, as the attribute wants.
		"request_memory          = 16384",
		// The argument is MiB but RequestDisk is KiB, so this must be
		// 30720 * 1024. Getting the conversion wrong silently asks for
		// a thirtieth of the disk.
		"request_disk            = 31457280",
		// Verification gates publication through these two together.
		"when_to_transfer_output = ON_SUCCESS",
		"+JobSuccessExitCode     = 0",
		"transfer_output_files   = image.sif",
		`transfer_output_remaps  = "image.sif = osdf:///chtc/staging/b/alice/py311.sif"`,
		"requirements            = TARGET.HasApptainer",
		"+IsBuildJob = True",
		"queue",
	}
	for _, want := range mustContain {
		if !strings.Contains(got, want) {
			t.Errorf("submit file missing %q\n--- got ---\n%s", want, got)
		}
	}

	// Resource values must never carry a unit suffix: the submit parser
	// has mishandled those, and a bare number in the attribute's own
	// unit cannot be misread.
	for _, bad := range []string{"GB", "MB", "16G", "30G"} {
		if strings.Contains(got, bad) {
			t.Errorf("submit file contains the unit suffix %q; resources must be bare numbers\n%s", bad, got)
		}
	}
}

func TestBuildSubmitFileOmitsUnsetSiteConfig(t *testing.T) {
	got := buildSubmitFile(buildSettings{defCpus: 1, defMemoryMB: 1, defDiskMB: 1},
		"osdf:///x/y.sif", 1, 1, 1)
	if strings.Contains(got, "requirements") {
		t.Errorf("an unset requirements must not emit an empty expression:\n%s", got)
	}
	if strings.Contains(got, "HTTP_API_BUILD_EXTRA_SUBMIT") {
		t.Errorf("an unset extra-submit block must not emit its header:\n%s", got)
	}
}

func TestBuildScriptGatesPublicationOnVerify(t *testing.T) {
	withVerify := buildScript("python3 -c 'import numpy'")

	for _, want := range []string{
		"apptainer build image.sif image.def",
		"apptainer_build_exit=$rc",
		// The build's own failure must stop the script before the
		// verify step, or the log describes the wrong problem.
		`if [ "$rc" -ne 0 ]; then`,
		"apptainer exec image.sif python3 -c 'import numpy'",
		"verify_exit=$rc",
		"will NOT be published",
		// The cache is the largest thing in the sandbox and must not
		// survive to be considered for transfer.
		"cleanup",
		"APPTAINER_CACHEDIR",
		"APPTAINER_TMPDIR",
	} {
		if !strings.Contains(withVerify, want) {
			t.Errorf("build script missing %q\n--- got ---\n%s", want, withVerify)
		}
	}

	// Without a verify command there must be no verify block at all,
	// rather than an empty `apptainer exec image.sif` that would fail
	// and suppress a perfectly good image.
	noVerify := buildScript("")
	if strings.Contains(noVerify, "=== verify ===") {
		t.Errorf("a build with no verify command must not emit a verify block:\n%s", noVerify)
	}
	if strings.Contains(noVerify, "apptainer exec image.sif \n") ||
		strings.Contains(noVerify, "apptainer exec image.sif\n") {
		t.Errorf("empty verify produced a bare apptainer exec:\n%s", noVerify)
	}
	if !strings.Contains(noVerify, "apptainer build image.sif image.def") {
		t.Errorf("a build with no verify command must still build:\n%s", noVerify)
	}
}

// The tool must be in the catalogue, or none of the above is reachable.
func TestBuildContainerToolDeclared(t *testing.T) {
	tool := buildContainerTool()
	if tool.Name != "build_container" {
		t.Fatalf("tool name = %q", tool.Name)
	}
	props, ok := tool.InputSchema["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("input schema has no properties")
	}
	for _, arg := range []string{"definition", "name", "destination", "verify", "cpus", "memory_mb", "disk_mb"} {
		if _, ok := props[arg]; !ok {
			t.Errorf("input schema is missing the %q argument", arg)
		}
	}
	req, ok := tool.InputSchema["required"].([]string)
	if !ok || len(req) != 2 {
		t.Fatalf("required = %v, want definition and name", tool.InputSchema["required"])
	}
}
