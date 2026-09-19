// Container builds: submit an Apptainer definition as a job on the pool's
// build slots and stage the resulting image to object storage.
//
// The tool takes a definition file verbatim rather than a spec it renders
// into one. Apptainer's definition language is the thing users already
// know and already have in version control, and any spec we invented
// would need an escape hatch back to it within a release.
//
// What the tool does add is the part that is not in the definition file
// and that a caller cannot be expected to know: which slots accept build
// jobs, what resources to ask for, that the image cache must be kept out
// of the transfer set, and that a built image should be exercised before
// it is published. All of that is site policy or hard-won detail, and all
// of it is what people get wrong when they copy a submit file from a docs
// page.
//
// Stageout is HTCondor's, not ours. transfer_output_remaps hands the
// image to the file-transfer plugin, which already knows how to use the
// job's OAuth credential; an in-job upload would reimplement that badly.
// Verification gates it through when_to_transfer_output = ON_SUCCESS: a
// nonzero exit transfers nothing, so an image that fails its own smoke
// test is never published.

package mcpserver

import (
	"context"
	"fmt"
	"path"
	"strings"
	"testing/fstest"

	"github.com/bbockelm/golang-htcondor/logging"
)

// Built-in resource defaults, used when the operator sets none. They match
// what CHTC's documentation asks for on a build slot, which is a
// reasonable shape for an image build anywhere: enough cores for parallel
// package installs and enough scratch for the unpacked root filesystem.
const (
	defaultBuildCpus     = 8
	defaultBuildMemoryMB = 16384
	defaultBuildDiskMB   = 30720
)

// buildImageName is the filename the job writes and transfers. It is
// fixed rather than derived from the caller's name so that the submit
// file, the script and the remap cannot disagree with each other; the
// caller's chosen name appears only in the destination URL.
const buildImageName = "image.sif"

// buildDefName is the definition file as spooled into the job.
const buildDefName = "image.def"

func buildContainerTool() Tool {
	return Tool{
		Name: "build_container",
		Description: "Build an Apptainer/Singularity container image from a definition file, as a job on the pool's build machines, " +
			"and publish the resulting .sif to object storage.\n" +
			"Pass the definition file contents verbatim in `definition` — the same text you would give to `apptainer build`. " +
			"The tool supplies what the definition does not: the submit attributes that reach build-capable slots, resource requests, " +
			"cache handling, and the transfer of the finished image.\n" +
			"This returns as soon as the job is submitted, because a real image takes minutes to build. " +
			"Wait for it with watch_jobs (event=\"done\"), then read get_job_stdout / get_job_stderr for the build log. " +
			"A build that fails, or whose `verify` command fails, publishes nothing — but its logs still come back, so the failure is diagnosable.\n" +
			"Prefer `verify`: an image that cannot run the thing it was built for is worse than no image, because it reaches a shared path " +
			"where other people may pick it up.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"definition": map[string]interface{}{
					"type": "string",
					"description": "Apptainer definition file contents, e.g. a \"Bootstrap: docker\" header followed by %post/%environment/%runscript sections. " +
						"Passed to `apptainer build` unchanged.",
				},
				"name": map[string]interface{}{
					"type": "string",
					"description": "Filename to publish as, e.g. \"py311.sif\". A bare filename, not a path. " +
						"Combined with the site's configured staging base when `destination` is omitted.",
				},
				"destination": map[string]interface{}{
					"type": "string",
					"description": "Full destination URL for the finished image, e.g. \"osdf:///chtc/staging/b/alice/py311.sif\". " +
						"Optional when the site configures a staging base, in which case `name` is appended to it " +
						"(the base may be per-user, resolved from your authenticated identity). " +
						"The destination directory must already exist: object stores do not create one on write, and the job fails if it is missing.",
				},
				"verify": map[string]interface{}{
					"type": "string",
					"description": "Shell command run inside the freshly built image, e.g. \"python3 -c 'import numpy'\". " +
						"If it exits nonzero the image is NOT published. Omit to publish without checking.",
				},
				"cpus":      map[string]interface{}{"type": "integer", "description": "CPU cores for the build."},
				"memory_mb": map[string]interface{}{"type": "integer", "description": "Memory in MiB for the build."},
				"disk_mb":   map[string]interface{}{"type": "integer", "description": "Scratch disk in MiB. Must hold the unpacked root filesystem plus the image plus the layer cache — several times the finished image size."},
			},
			"required": []string{"definition", "name"},
		},
	}
}

// buildSettings is the site's build configuration, resolved once per call
// so the defaults and caps are applied in one place.
type buildSettings struct {
	extraSubmit  string
	requirements string
	stagingBase  string
	defCpus      int
	defMemoryMB  int
	defDiskMB    int
	maxCpus      int
	maxMemoryMB  int
	maxDiskMB    int
}

// BuildConfig is the operator's container-build configuration. It is one
// struct rather than a handful of fields because it threads through the
// HTTP handler to the MCP server, and nine separate knobs would be nine
// chances for a layer to drop one.
//
// Sizes are in the units a caller would write: MiB for memory and for
// disk. The tool converts disk to the KiB that RequestDisk wants.
type BuildConfig struct {
	// ExtraSubmit (HTTP_API_BUILD_EXTRA_SUBMIT) is the site's
	// build-specific submit block: the attribute that marks a build job,
	// plus anything else the site wants on one, such as keep_claim_idle
	// so successive builds reuse a claim.
	ExtraSubmit string
	// Requirements (HTTP_API_BUILD_REQUIREMENTS) selects build-capable
	// slots at a site where no transform does it.
	Requirements string
	// StagingBase (HTTP_API_BUILD_STAGING_BASE) is the URL images are
	// published under when the caller gives a bare name. Empty means
	// every call must name its own destination.
	//
	// It may be a template. {user} expands to the authenticated caller
	// and {initial} to the first letter of that name, so a site whose
	// staging area is per user can be described:
	//
	//	osdf:///chtc/staging/{initial}/{user}
	//
	// A base with no placeholders is used verbatim.
	StagingBase string

	DefaultCpus     int
	DefaultMemoryMB int
	DefaultDiskMB   int

	// Caps. Zero means uncapped. These matter because build slots are
	// large -- CHTC's are 128-core, 256 GB machines -- and an agent
	// asking for "plenty" should not be able to claim one whole.
	MaxCpus     int
	MaxMemoryMB int
	MaxDiskMB   int
}

// buildSettingsFromConfig resolves the site's build configuration once,
// at construction, filling in the built-in defaults for anything the
// operator left unset.
func buildSettingsFromConfig(cfg Config) buildSettings {
	b := buildSettings{
		extraSubmit:  cfg.Build.ExtraSubmit,
		requirements: cfg.Build.Requirements,
		stagingBase:  cfg.Build.StagingBase,
		defCpus:      cfg.Build.DefaultCpus,
		defMemoryMB:  cfg.Build.DefaultMemoryMB,
		defDiskMB:    cfg.Build.DefaultDiskMB,
		maxCpus:      cfg.Build.MaxCpus,
		maxMemoryMB:  cfg.Build.MaxMemoryMB,
		maxDiskMB:    cfg.Build.MaxDiskMB,
	}
	if b.defCpus <= 0 {
		b.defCpus = defaultBuildCpus
	}
	if b.defMemoryMB <= 0 {
		b.defMemoryMB = defaultBuildMemoryMB
	}
	if b.defDiskMB <= 0 {
		b.defDiskMB = defaultBuildDiskMB
	}
	return b
}

// clamp applies the caller's request against the site default and cap. A
// request above the cap is lowered rather than refused: the build still
// runs, and refusing would make an agent guess at a number the operator
// never told it.
func clampBuildResource(requested, fallback, limit int) int {
	v := requested
	if v <= 0 {
		v = fallback
	}
	if limit > 0 && v > limit {
		v = limit
	}
	return v
}

func (s *Server) toolBuildContainer(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	definition := stringArg(args, "definition")
	if strings.TrimSpace(definition) == "" {
		return nil, fmt.Errorf("definition is required: pass the Apptainer definition file contents")
	}

	name := strings.TrimSpace(stringArg(args, "name"))
	if err := validateBuildName(name); err != nil {
		return nil, err
	}

	cfg := s.build

	// The caller is resolved even when the staging base needs no
	// expansion, so that a site switching to a per-user template does not
	// discover only then that identification was failing. An
	// unidentifiable caller is fatal for a template and harmless for a
	// fixed base, which buildDestination decides.
	var owner string
	if caller, err := s.liveJobCaller(ctx); err == nil {
		owner = caller.Owner
	}

	destination, err := buildDestination(stringArg(args, "destination"), cfg.stagingBase, name, owner)
	if err != nil {
		return nil, err
	}

	verify := strings.TrimSpace(stringArg(args, "verify"))

	cpus := clampBuildResource(intArg(args, "cpus", 0), cfg.defCpus, cfg.maxCpus)
	memoryMB := clampBuildResource(intArg(args, "memory_mb", 0), cfg.defMemoryMB, cfg.maxMemoryMB)
	diskMB := clampBuildResource(intArg(args, "disk_mb", 0), cfg.defDiskMB, cfg.maxDiskMB)

	submitFile := buildSubmitFile(cfg, destination, cpus, memoryMB, diskMB)

	schedd := s.getSchedd()
	clusterID, procAds, err := schedd.SubmitRemote(ctx, s.submitPolicy.Apply(submitFile))
	if err != nil {
		return nil, fmt.Errorf("build job submission failed: %w", err)
	}

	// The script and the definition go in as spooled input rather than
	// via a temp file on the access point: the server may not be running
	// as the submitting user, and a file on disk would need cleaning up
	// on every failure path.
	stage := fstest.MapFS{
		"build.sh":   &fstest.MapFile{Data: []byte(buildScript(verify)), Mode: 0o755},
		buildDefName: &fstest.MapFile{Data: []byte(definition), Mode: 0o644},
	}
	if err := schedd.SpoolJobFilesFromFS(ctx, procAds, stage); err != nil {
		s.removeBuildJob(ctx, clusterID, "spooling the build inputs failed")
		return nil, fmt.Errorf("the schedd accepted the build job but spooling its inputs failed: %w", err)
	}

	jobID := fmt.Sprintf("%d.0", clusterID)
	verifyNote := "no verify command was given, so the image is published if the build succeeds"
	if verify != "" {
		verifyNote = fmt.Sprintf("the image is published only if %q succeeds inside it", verify)
	}

	return map[string]interface{}{
		"content": []map[string]interface{}{
			{
				"type": "text",
				"text": fmt.Sprintf(
					"Submitted build job %s for %s.\n"+
						"Destination on success: %s\n"+
						"Verification: %s.\n"+
						"Builds take minutes; wait with watch_jobs(constraint=\"ClusterId == %d\", event=\"done\"), "+
						"then read get_job_stdout(%q) for the build log. On failure nothing is published and "+
						"get_job_stderr(%q) carries the reason.",
					jobID, name, destination, verifyNote, clusterID, jobID, jobID),
			},
		},
		"metadata": map[string]interface{}{
			"cluster_id":  clusterID,
			"job_id":      jobID,
			"name":        name,
			"destination": destination,
			"verify":      verify,
			"cpus":        cpus,
			"memory_mb":   memoryMB,
			"disk_mb":     diskMB,
		},
	}, nil
}

// removeBuildJob cleans up a job whose inputs never arrived. Best effort:
// the caller is already returning an error, and a leftover held job is a
// smaller problem than masking that error with this one.
func (s *Server) removeBuildJob(ctx context.Context, clusterID int, reason string) {
	if _, err := s.getSchedd().RemoveJobs(ctx, fmt.Sprintf("ClusterId == %d", clusterID), reason); err != nil {
		s.logger.Warn(logging.DestinationMCP, "could not remove a build job after a spooling failure",
			"cluster_id", clusterID, "error", err)
	}
}

// validateBuildName rejects anything that is not a bare filename. The
// name reaches a destination URL, so a path separator or a "." component
// would silently publish somewhere other than where the caller meant.
func validateBuildName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("name is required, e.g. \"py311.sif\"")
	case strings.ContainsAny(name, "/\\"):
		return fmt.Errorf("name must be a bare filename, not a path: got %q", name)
	case name == "." || name == "..":
		return fmt.Errorf("name must be a filename: got %q", name)
	case strings.HasPrefix(name, "-"):
		return fmt.Errorf("name must not start with a dash, which shells and tools read as an option: got %q", name)
	case !strings.HasSuffix(name, ".sif"):
		return fmt.Errorf("name must end in .sif, which is what apptainer writes: got %q", name)
	}
	return nil
}

// buildDestination resolves where the finished image goes.
//
// owner is the authenticated caller, used to expand a per-user staging
// template. It is empty only when the server could not identify the
// caller, which is an error for a template and irrelevant for a fixed
// base.
func buildDestination(destination, stagingBase, name, owner string) (string, error) {
	destination = strings.TrimSpace(destination)
	if destination != "" {
		if !strings.Contains(destination, "://") {
			return "", fmt.Errorf("destination must be a URL with a transfer scheme such as osdf:// or pelican://, got %q", destination)
		}
		return destination, nil
	}
	if stagingBase == "" {
		return "", fmt.Errorf("no destination given and this server has no staging base configured "+
			"(HTTP_API_BUILD_STAGING_BASE); pass destination as a full URL, e.g. osdf:///chtc/staging/b/alice/%s", name)
	}
	base, err := expandStagingBase(stagingBase, owner)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(base, "/") + "/" + path.Base(name), nil
}

// Placeholders accepted in HTTP_API_BUILD_STAGING_BASE.
const (
	stagingPlaceholderUser    = "{user}"
	stagingPlaceholderInitial = "{initial}"
)

// expandStagingBase substitutes the caller into a staging template.
//
// A site whose staging area is per user cannot be described by a fixed
// prefix. CHTC's is /chtc/staging/<initial>/<netid>, so the useful
// configuration is a template:
//
//	osdf:///chtc/staging/{initial}/{user}
//
// A base with no placeholders is returned unchanged, so a site with one
// shared area keeps working without knowing this exists.
//
// The owner comes from the authenticated caller, never from the request,
// so a caller cannot aim the expansion at somebody else's directory. It
// is still validated here: this value becomes part of a path, and a
// username carrying a separator or a ".." would walk out of the staging
// area. Defense in depth against an identity source that admits one.
func expandStagingBase(base, owner string) (string, error) {
	hasUser := strings.Contains(base, stagingPlaceholderUser)
	hasInitial := strings.Contains(base, stagingPlaceholderInitial)
	if !hasUser && !hasInitial {
		// Reject a leftover brace rather than publishing to a path with
		// a literal "{netid}" in it, which would look like it worked.
		if i := strings.IndexByte(base, '{'); i >= 0 {
			return "", fmt.Errorf("staging base %q contains an unknown placeholder at %q; "+
				"only %s and %s are substituted", base, base[i:], stagingPlaceholderUser, stagingPlaceholderInitial)
		}
		return base, nil
	}

	if owner == "" {
		return "", fmt.Errorf("staging base %q is per-user but the caller could not be identified; "+
			"pass an explicit destination instead", base)
	}
	if err := validateStagingOwner(owner); err != nil {
		return "", err
	}

	expanded := strings.ReplaceAll(base, stagingPlaceholderUser, owner)
	if hasInitial {
		expanded = strings.ReplaceAll(expanded, stagingPlaceholderInitial, strings.ToLower(owner[:1]))
	}
	if i := strings.IndexByte(expanded, '{'); i >= 0 {
		return "", fmt.Errorf("staging base %q contains an unknown placeholder at %q; "+
			"only %s and %s are substituted", base, expanded[i:], stagingPlaceholderUser, stagingPlaceholderInitial)
	}
	return expanded, nil
}

// validateStagingOwner rejects a username that would not be safe as a
// path component.
func validateStagingOwner(owner string) error {
	if strings.ContainsAny(owner, "/\\") {
		return fmt.Errorf("cannot build a per-user staging path: the caller name %q contains a path separator", owner)
	}
	if owner == "." || owner == ".." || strings.Contains(owner, "..") {
		return fmt.Errorf("cannot build a per-user staging path: the caller name %q is not a usable path component", owner)
	}
	return nil
}

// buildSubmitFile renders the submit file for a build job.
//
// Resource values are emitted as bare numbers in the attributes' own
// units, never with a "GB" suffix, so the result does not depend on how
// the submit parser handles suffixes.
func buildSubmitFile(cfg buildSettings, destination string, cpus, memoryMB, diskMB int) string {
	var sb strings.Builder

	sb.WriteString("universe                = vanilla\n")
	sb.WriteString("executable              = build.sh\n")
	sb.WriteString("transfer_executable     = true\n")
	fmt.Fprintf(&sb, "transfer_input_files    = %s\n", buildDefName)

	fmt.Fprintf(&sb, "request_cpus            = %d\n", cpus)
	fmt.Fprintf(&sb, "request_memory          = %d\n", memoryMB)
	// RequestDisk is in KiB while the argument is MiB.
	fmt.Fprintf(&sb, "request_disk            = %d\n", diskMB*1024)

	sb.WriteString("should_transfer_files   = YES\n")

	// ON_SUCCESS is what makes verification gate publication: on a
	// nonzero exit HTCondor transfers no output files, so a failed build
	// or a failed smoke test publishes nothing. stdout and stderr come
	// back either way, so the failure is still diagnosable.
	//
	// JobSuccessExitCode is set as a raw attribute rather than through
	// the submit command `success_exit_code`, which writes the wrong
	// attribute name in this parser. Emitting the attribute directly is
	// correct regardless of whether that fix has landed.
	sb.WriteString("when_to_transfer_output = ON_SUCCESS\n")
	sb.WriteString("+JobSuccessExitCode     = 0\n")

	fmt.Fprintf(&sb, "transfer_output_files   = %s\n", buildImageName)
	fmt.Fprintf(&sb, "transfer_output_remaps  = \"%s = %s\"\n", buildImageName, destination)

	if req := strings.TrimSpace(cfg.requirements); req != "" {
		fmt.Fprintf(&sb, "requirements            = %s\n", req)
	}
	if extra := strings.TrimSpace(cfg.extraSubmit); extra != "" {
		sb.WriteString("\n# --- Site build settings (HTTP_API_BUILD_EXTRA_SUBMIT) ---\n")
		sb.WriteString(extra)
		if !strings.HasSuffix(extra, "\n") {
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\nqueue\n")
	return sb.String()
}

// buildScript is the job's executable.
//
// Every step reports its own exit status and the script stops at the
// first failure, because the alternative -- letting a failed build fall
// through to a verification step that then fails for a different reason
// -- produces a log that describes the wrong problem.
func buildScript(verify string) string {
	var sb strings.Builder

	sb.WriteString(`#!/bin/bash
# Generated by htcondor-api build_container.
#
# Exit status decides publication: the submit file sets
# when_to_transfer_output = ON_SUCCESS, so any nonzero exit here transfers
# no image. stdout and stderr come back regardless.

echo "=== build host ==="
hostname
echo "cpus=$(nproc)"
df -h . | awk 'NR==2 {print "scratch_free=" $4}'

if ! command -v apptainer >/dev/null 2>&1; then
    echo "apptainer is not installed on this machine." 1>&2
    echo "The job reached a slot that cannot build images; check the site's build-slot" 1>&2
    echo "requirements (HTTP_API_BUILD_REQUIREMENTS / HTTP_API_BUILD_EXTRA_SUBMIT)." 1>&2
    exit 127
fi
apptainer --version

# Keep the layer cache and the build's temporary root filesystem inside
# the scratch directory, then delete them. Left in place they are the
# largest things in the sandbox, and anything still there at exit is a
# candidate for transfer back to the access point.
export APPTAINER_CACHEDIR="$PWD/.apptainer-cache"
export APPTAINER_TMPDIR="$PWD/.apptainer-tmp"
mkdir -p "$APPTAINER_CACHEDIR" "$APPTAINER_TMPDIR"
cleanup() { rm -rf "$APPTAINER_CACHEDIR" "$APPTAINER_TMPDIR"; }

echo
echo "=== definition ==="
cat `)
	sb.WriteString(buildDefName)
	sb.WriteString(`

echo
echo "=== build ==="
`)
	fmt.Fprintf(&sb, "apptainer build %s %s\n", buildImageName, buildDefName)
	sb.WriteString(`rc=$?
echo "apptainer_build_exit=$rc"
if [ "$rc" -ne 0 ]; then
    cleanup
    exit "$rc"
fi

echo
echo "=== image ==="
`)
	fmt.Fprintf(&sb, "ls -lh %s\n", buildImageName)
	fmt.Fprintf(&sb, "apptainer inspect %s\n", buildImageName)

	if verify != "" {
		sb.WriteString(`
echo
echo "=== verify ==="
`)
		fmt.Fprintf(&sb, "apptainer exec %s %s\n", buildImageName, verify)
		sb.WriteString(`rc=$?
echo "verify_exit=$rc"
if [ "$rc" -ne 0 ]; then
    echo "verification failed; the image will NOT be published" 1>&2
    cleanup
    exit "$rc"
fi
`)
	}

	sb.WriteString(`
cleanup
echo
echo "=== build complete; the image is being published ==="
exit 0
`)
	return sb.String()
}
