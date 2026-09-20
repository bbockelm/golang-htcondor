package mcpserver

import (
	"os/exec"
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
	got := buildSubmitFile(cfg, "osdf:///chtc/staging/b/alice/py311.sif", 8, 16384, 30720, false)

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
		// Without these the job has no Out or Err and a failed build is
		// unreadable; see TestBuildSubmitFileKeepsTheLogOnFailure.
		"output                  = build.out",
		"error                   = build.err",
		"log                     = build.log",
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
		"osdf:///x/y.sif", 1, 1, 1, false)
	if strings.Contains(got, "requirements") {
		t.Errorf("an unset requirements must not emit an empty expression:\n%s", got)
	}
	if strings.Contains(got, "HTTP_API_BUILD_EXTRA_SUBMIT") {
		t.Errorf("an unset extra-submit block must not emit its header:\n%s", got)
	}
}

// The failure path is the one that matters: a build that works needs no
// log, and a build that does not is worthless without one. The submit
// file has to satisfy two things at once -- withhold the image on a
// nonzero exit, and return the log anyway -- and it is easy to render a
// submit file that does the first and quietly drops the second.
func TestBuildSubmitFileKeepsTheLogOnFailure(t *testing.T) {
	got := buildSubmitFile(buildSettings{}, "osdf:///x/py311.sif", 1, 1, 1, false)

	// Naming Out and Err is the whole mechanism. HTCondor sends a failed
	// job's stdout and stderr back as failure files; a job that names
	// neither has nothing to send, which is how a build that exited 255
	// produced zero recoverable bytes.
	for _, want := range []string{
		"output                  = build.out",
		"error                   = build.err",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("submit file missing %q; a failed build would be unreadable\n--- got ---\n%s", want, got)
		}
	}

	// ...and the gate it has to coexist with. If either of these goes
	// away a failed verify starts publishing its image, which is worse
	// than an unreadable log.
	for _, want := range []string{
		"when_to_transfer_output = ON_SUCCESS",
		"+JobSuccessExitCode     = 0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("submit file missing %q; a failed build would publish its image\n--- got ---\n%s", want, got)
		}
	}

	// Streaming must NOT be how we do this. HTCondor's
	// FileTransfer::shouldSendStdout() drops a streamed file from the
	// failure-file set, so asking to stream would trade the guarantee
	// above for a weaker one -- and this repo's submit parser writes
	// stream_output to the attribute `StreamOutput`, which HTCondor does
	// not read (it wants `StreamOut`), so the request would not even
	// arrive. Either way it is the wrong lever.
	for _, bad := range []string{"stream_output", "stream_error", "StreamOut", "StreamErr"} {
		if strings.Contains(got, bad) {
			t.Errorf("submit file asks for %q; streaming removes stdout from the failure-file set "+
				"that makes a failed build readable\n--- got ---\n%s", bad, got)
		}
	}
}

// The image must still be the only thing published. Naming the log is
// only safe because the log is not an output file: if it ever reached
// transfer_output_files it would be remapped to the destination URL
// alongside -- or instead of -- the image.
func TestBuildSubmitFileTransfersOnlyTheImage(t *testing.T) {
	got := buildSubmitFile(buildSettings{}, "osdf:///x/py311.sif", 1, 1, 1, false)

	if !strings.Contains(got, "transfer_output_files   = image.sif\n") {
		t.Errorf("transfer_output_files must name the image and nothing else\n--- got ---\n%s", got)
	}
	if !strings.Contains(got, `transfer_output_remaps  = "image.sif = osdf:///x/py311.sif"`) {
		t.Errorf("only the image may be remapped to the destination\n--- got ---\n%s", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if !strings.HasPrefix(line, "transfer_output") {
			continue
		}
		for _, logFile := range []string{"build.out", "build.err", "build.log"} {
			if strings.Contains(line, logFile) {
				t.Errorf("the log file %q appears in %q; it must not be transferred as output, "+
					"the remap would send it to the destination URL", logFile, line)
			}
		}
	}
}

// Bug: apptainer is on the job's PATH but mksquashfs, which it execs to
// write the .sif, is in /usr/sbin and is not. The build then fails with
// an exit status and a message that names nothing.
func TestBuildScriptPutsSbinOnPathBeforeUsingApptainer(t *testing.T) {
	script := buildScript(true)

	pathAt := strings.Index(script, `PATH="${PATH:-`)
	if pathAt < 0 {
		t.Fatalf("the script never extends PATH:\n%s", script)
	}

	// The directories mksquashfs and its friends actually live in.
	pathLine := script[pathAt : strings.Index(script[pathAt:], "\n")+pathAt]
	for _, dir := range []string{"/usr/local/sbin", "/usr/sbin", "/sbin"} {
		if !strings.Contains(pathLine, dir) {
			t.Errorf("PATH assignment %q does not add %s", pathLine, dir)
		}
	}
	// The job's own PATH has to survive: a site that put apptainer
	// somewhere unusual did so deliberately, and a blind overwrite would
	// lose it.
	if !strings.Contains(pathLine, "${PATH") {
		t.Errorf("PATH assignment %q discards the job's existing PATH", pathLine)
	}
	if !strings.Contains(pathLine, "${PATH:-") {
		t.Errorf("PATH assignment %q has no fallback for an unset or empty PATH", pathLine)
	}
	if !strings.Contains(script[pathAt:], "export PATH") {
		t.Errorf("the extended PATH is never exported, so apptainer's children do not see it:\n%s", script)
	}

	// Ordering is the assertion that matters. Extending PATH after the
	// first apptainer call would render exactly the same lines and fix
	// nothing.
	for _, after := range []string{
		"command -v apptainer",
		"command -v mksquashfs",
		"apptainer --version",
		"apptainer build image.sif image.def",
	} {
		at := strings.Index(script, after)
		if at < 0 {
			t.Errorf("the script never runs %q:\n%s", after, script)
			continue
		}
		if at < pathAt {
			t.Errorf("%q runs at offset %d, before PATH is extended at %d; "+
				"the build would search the job's original PATH", after, at, pathAt)
		}
	}
}

// The preflight exists so this failure never again presents as a bare
// ENOENT: apptainer reports a missing mksquashfs as "FATAL: no such file
// or directory" and names neither the tool nor where it looked.
func TestBuildScriptPreflightsMksquashfs(t *testing.T) {
	script := buildScript(false)

	at := strings.Index(script, "command -v mksquashfs")
	if at < 0 {
		t.Fatalf("no mksquashfs preflight:\n%s", script)
	}
	// It must stop the build rather than warn, and stop it before
	// apptainer produces the unattributable error.
	buildAt := strings.Index(script, "apptainer build image.sif image.def")
	if buildAt < at {
		t.Errorf("the mksquashfs preflight at %d runs after the build at %d", at, buildAt)
	}
	// Everything between the check and the build: the diagnosis.
	block := script[at:buildAt]
	for _, want := range []string{
		"mksquashfs",     // the tool, by name
		"PATH searched:", // and where we looked for it
		"squashfs-tools", // and how to get it
		"exit 127",       // and a stop, not a warning
	} {
		if !strings.Contains(block, want) {
			t.Errorf("the mksquashfs preflight does not mention %q; the point of the check is "+
				"that its message says what apptainer's does not\n--- got ---\n%s", want, block)
		}
	}

	// The resolved locations go in the log too, so the next build that
	// fails for a neighbouring reason has the evidence already.
	for _, want := range []string{`echo "path=$PATH"`, "echo \"mksquashfs=$(command -v mksquashfs)\""} {
		if !strings.Contains(script, want) {
			t.Errorf("the script does not record %q in its log:\n%s", want, script)
		}
	}
}

// The script is generated text that nothing compiles, so a quoting
// mistake in it would reach a build slot before anyone noticed.
func TestBuildScriptIsValidShell(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatalf("bash is required to check the generated build script: %v", err)
	}

	for _, hasVerify := range []bool{false, true} {
		script := buildScript(hasVerify)
		cmd := exec.CommandContext(t.Context(), bash, "-n", "/dev/stdin") //nolint:gosec // G204: bash from LookPath, script on stdin
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("generated script (hasVerify=%v) is not valid bash: %v\n%s\n--- script ---\n%s",
				hasVerify, err, out, script)
		}
	}

	// Evaluate the PATH line itself rather than trusting that it reads
	// correctly: this is the one line whose behaviour depends on shell
	// expansion rather than on the text we asserted above.
	script := buildScript(false)
	pathAt := strings.Index(script, `PATH="${PATH:-`)
	if pathAt < 0 {
		t.Fatal("the script never extends PATH")
	}
	pathLine := script[pathAt : strings.Index(script[pathAt:], "\n")+pathAt]

	for _, tc := range []struct{ name, start, wantContains string }{
		{"the job's PATH is preserved", "/opt/site/bin:/usr/bin", "/opt/site/bin:/usr/bin:"},
		{"an empty PATH still gets the standard dirs", "", "/usr/bin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			//nolint:gosec // G204: bash from LookPath; the script is this package's own generated text
			cmd := exec.CommandContext(t.Context(), bash, "-c", "PATH="+shellQuote(tc.start)+"\n"+pathLine+"\nprintf %s \"$PATH\"")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("evaluating %q failed: %v\n%s", pathLine, err, out)
			}
			got := string(out)
			if !strings.Contains(got, tc.wantContains) {
				t.Errorf("PATH=%q gave %q, want it to contain %q", tc.start, got, tc.wantContains)
			}
			if !strings.Contains(got, "/usr/sbin") {
				t.Errorf("PATH=%q gave %q, which has no /usr/sbin; mksquashfs would not be found", tc.start, got)
			}
		})
	}
}

// shellQuote wraps a value in single quotes for the test's own `bash -c`.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func TestBuildScriptGatesPublicationOnVerify(t *testing.T) {
	withVerify := buildScript(true)

	for _, want := range []string{
		"apptainer build image.sif image.def",
		"apptainer_build_exit=$rc",
		// The build's own failure must stop the script before the
		// verify step, or the log describes the wrong problem.
		`if [ "$rc" -ne 0 ]; then`,
		// The command is read from the spooled file, not pasted in.
		"apptainer exec image.sif /bin/sh -c \"$(cat verify.cmd)\"",
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
	noVerify := buildScript(false)
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

// A verify command must never become script text. Pasting it in meant a
// newline injected lines AFTER the check that reads its exit status, so
// "true\nexit 0" published an image that was never verified -- the one
// thing this feature exists to prevent.
func TestVerifyCommandIsNotScriptText(t *testing.T) {
	script := buildScript(true)

	// Whatever the caller wrote, none of it is in the script.
	// Distinctive strings only: "\nexit 0" would also match the script's
	// own legitimate final exit, and a needle that cannot tell injected
	// text from the real thing is not a test.
	for _, injected := range []string{"exit 0   # injected", "rm -rf /"} {
		if strings.Contains(script, injected) {
			t.Errorf("the build script contains caller-supplied text %q:\n%s", injected, script)
		}
	}
	// It is read from the spooled file and passed as ONE argument to sh.
	if !strings.Contains(script, `/bin/sh -c "$(cat verify.cmd)"`) {
		t.Errorf("verify must be read from %s and passed as a single argument:\n%s", buildVerifyName, script)
	}
	// And the exit status is still what gates publication.
	if !strings.Contains(script, "verify_exit=$rc") || !strings.Contains(script, "will NOT be published") {
		t.Errorf("verify must still gate publication:\n%s", script)
	}
}

// The verify file has to be spooled AND listed as an input, or the build
// fails reading a file that was never transferred.
func TestVerifyFileIsTransferred(t *testing.T) {
	with := buildSubmitFile(buildSettings{defCpus: 1, defMemoryMB: 1, defDiskMB: 1},
		"osdf:///x/y.sif", 1, 1, 1, true)
	if !strings.Contains(with, "transfer_input_files    = image.def, verify.cmd") {
		t.Errorf("verify.cmd must be transferred when a verify command is given:\n%s", with)
	}

	without := buildSubmitFile(buildSettings{defCpus: 1, defMemoryMB: 1, defDiskMB: 1},
		"osdf:///x/y.sif", 1, 1, 1, false)
	if strings.Contains(without, "verify.cmd") {
		t.Errorf("verify.cmd must not be requested when there is no verify command:\n%s", without)
	}
}

// Exiting 0 without the image would make HTCondor report a transfer
// failure naming the remap -- blaming the destination for a build that
// silently produced nothing.
func TestScriptRefusesSuccessWithoutAnImage(t *testing.T) {
	for _, script := range []string{buildScript(true), buildScript(false)} {
		if !strings.Contains(script, "if [ ! -s image.sif ]; then") {
			t.Errorf("the script must not report success without the image:\n%s", script)
		}
	}
}
