package httpserver

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBuildJupyterSubmitFile_Docker covers the Linux + docker path: the
// generated submit file should pin the docker image, ship the launcher
// script as the executable, and constrain the architecture (no OpSys
// constraint — docker handles the OS layer).
func TestBuildJupyterSubmitFile_Docker(t *testing.T) {
	got := buildJupyterSubmitFile(jupyterSubmitArgs{
		InstanceID:   "deadbeef",
		Image:        "quay.io/jupyter/scipy-notebook:latest",
		Cpus:         2,
		MemoryMB:     4096,
		DiskMB:       4096,
		Universe:     "docker",
		HelperGOOS:   "linux",
		HelperGOARCH: "arm64",
	})

	mustContain(t, got, "universe = docker")
	mustContain(t, got, "docker_image = quay.io/jupyter/scipy-notebook:latest")
	mustContain(t, got, "executable = jupyter-launch.sh")
	mustContain(t, got, "transfer_executable = true")
	mustContain(t, got, "transfer_input_files = htcondor-jupyter-helper, jupyter-token")
	mustContain(t, got, "request_cpus = 2")
	mustContain(t, got, "request_memory = 4096")
	mustContain(t, got, "request_disk = 4096")
	// arm64 builds match either macOS-style "arm64" or Linux-style "AARCH64"
	mustContain(t, got, `requirements = ((Arch == "arm64" || Arch == "AARCH64"))`)
	// Linux/docker case: no OpSys pin.
	if strings.Contains(got, "OpSys") {
		t.Errorf("docker submit file should not pin OpSys; got:\n%s", got)
	}
	mustContain(t, got, "queue\n")
}

// TestBuildJupyterSubmitFile_DefaultTransferInputs verifies the
// default transfer_input_files when no explicit list is supplied —
// helper + token only.
func TestBuildJupyterSubmitFile_DefaultTransferInputs(t *testing.T) {
	got := buildJupyterSubmitFile(jupyterSubmitArgs{
		InstanceID:   "deadbeef",
		Image:        "x",
		Cpus:         1,
		MemoryMB:     256,
		DiskMB:       256,
		Universe:     "docker",
		HelperGOOS:   "linux",
		HelperGOARCH: "amd64",
	})
	mustContain(t, got, "transfer_input_files = htcondor-jupyter-helper, jupyter-token")
}

// TestBuildJupyterSubmitFile_WithCACert is the regression test for the
// ca.crt-not-transferred bug. When the caller adds "ca.crt" to
// TransferInputFiles, it must show up on the schedd-facing
// transfer_input_files line — otherwise we stage it in the spool but
// the schedd never ships it to the worker, and the helper fails with
// "open ca.crt: no such file or directory".
func TestBuildJupyterSubmitFile_WithCACert(t *testing.T) {
	got := buildJupyterSubmitFile(jupyterSubmitArgs{
		InstanceID:         "deadbeef",
		Image:              "x",
		Cpus:               1,
		MemoryMB:           256,
		DiskMB:             256,
		Universe:           "docker",
		HelperGOOS:         "linux",
		HelperGOARCH:       "amd64",
		TransferInputFiles: []string{"htcondor-jupyter-helper", "jupyter-token", "ca.crt"},
	})
	mustContain(t, got, "transfer_input_files = htcondor-jupyter-helper, jupyter-token, ca.crt")
}

// TestBuildJupyterSubmitFile_VanillaDarwin covers the macOS + vanilla
// path: no docker_image line, OpSys pinned to OSX, and the arm64
// expression unchanged.
func TestBuildJupyterSubmitFile_VanillaDarwin(t *testing.T) {
	got := buildJupyterSubmitFile(jupyterSubmitArgs{
		InstanceID:   "feedface",
		Cpus:         2,
		MemoryMB:     4096,
		DiskMB:       4096,
		Universe:     "vanilla",
		HelperGOOS:   "darwin",
		HelperGOARCH: "arm64",
	})

	mustContain(t, got, "universe = vanilla")
	if strings.Contains(got, "docker_image") {
		t.Errorf("vanilla submit file should not contain docker_image; got:\n%s", got)
	}
	mustContain(t, got, "executable = jupyter-launch.sh")
	mustContain(t, got, "transfer_executable = true")
	mustContain(t, got, `requirements = (OpSys == "macOS") && ((Arch == "arm64" || Arch == "AARCH64"))`)
}

// TestJupyterRequirementsExpr_amd64 confirms the amd64 case isn't
// touched by the macOS arm64 work — still plain X86_64.
func TestJupyterRequirementsExpr_amd64(t *testing.T) {
	got := jupyterRequirementsExpr("linux", "amd64")
	want := `(Arch == "X86_64")`
	if got != want {
		t.Errorf("linux/amd64 → %q, want %q", got, want)
	}
}

// TestJupyterUniverseForGOOS confirms the policy: macOS → vanilla,
// everything else → docker.
func TestJupyterUniverseForGOOS(t *testing.T) {
	if got := jupyterUniverseForGOOS("darwin"); got != "vanilla" {
		t.Errorf("darwin → %q, want vanilla", got)
	}
	if got := jupyterUniverseForGOOS("linux"); got != "docker" {
		t.Errorf("linux → %q, want docker", got)
	}
}

// TestJupyterHelperGOOSForUniverse confirms helper-GOOS selection.
func TestJupyterHelperGOOSForUniverse(t *testing.T) {
	// docker universe always wants the linux helper, even from a darwin host.
	goosOverride.Store("darwin")
	defer goosOverride.Store("")
	if got := jupyterHelperGOOSForUniverse("docker"); got != "linux" {
		t.Errorf("docker on darwin → %q, want linux", got)
	}
	// vanilla universe on a darwin host wants the darwin helper.
	if got := jupyterHelperGOOSForUniverse("vanilla"); got != "darwin" {
		t.Errorf("vanilla on darwin → %q, want darwin", got)
	}
	// vanilla universe on a linux host (hypothetical, not currently
	// reachable from the dispatcher) still wants the linux helper.
	goosOverride.Store("linux")
	if got := jupyterHelperGOOSForUniverse("vanilla"); got != "linux" {
		t.Errorf("vanilla on linux → %q, want linux", got)
	}
}

// TestBuildJupyterLaunchScript_Docker checks the docker-universe script:
// no conda fallback (the docker image provides jupyter), helper
// daemonize, and `exec jupyter lab` with the expected base_url.
func TestBuildJupyterLaunchScript_Docker(t *testing.T) {
	got := buildJupyterLaunchScript(jupyterLaunchScriptArgs{
		Universe:    "docker",
		UpstreamURL: "ws://api.example.com/api/v1/jupyter/instances/x/tunnel",
		BaseURL:     "/api/v1/jupyter/instances/x/proxy/",
		AllowOrigin: "http://api.example.com",
	})

	mustContain(t, got, "#!/usr/bin/env bash")
	mustContain(t, got, "./htcondor-jupyter-helper")
	mustContain(t, got, `--upstream "ws://api.example.com/api/v1/jupyter/instances/x/tunnel"`)
	mustContain(t, got, "--token-file ./jupyter-token")
	// Socket lives under /tmp via mktemp so we stay under the macOS
	// AF_UNIX 104-byte limit; the script binds the same path on both
	// the helper (--socket) and jupyter-lab (--ServerApp.sock).
	mustContain(t, got, `mktemp -d -t htcondor-jupyter`)
	mustContain(t, got, `--socket "$SOCK"`)
	mustContain(t, got, `--ServerApp.sock="$SOCK"`)
	mustContain(t, got, `trap 'rm -rf "$SOCK_DIR"' EXIT`)
	mustContain(t, got, "--daemonize")
	mustContain(t, got, "exec jupyter lab")
	mustContain(t, got, `--ServerApp.base_url="/api/v1/jupyter/instances/x/proxy/"`)
	mustContain(t, got, `--ServerApp.allow_origin="http://api.example.com"`)
	// Docker case: no conda dance.
	if strings.Contains(got, "conda create") {
		t.Errorf("docker launch script should not contain conda fallback; got:\n%s", got)
	}
}

// TestBuildJupyterLaunchScript_Vanilla checks that the vanilla path
// includes the conda / venv fallback chain.
func TestBuildJupyterLaunchScript_Vanilla(t *testing.T) {
	got := buildJupyterLaunchScript(jupyterLaunchScriptArgs{
		Universe:    "vanilla",
		UpstreamURL: "wss://x.example/api/v1/jupyter/instances/y/tunnel",
		BaseURL:     "/api/v1/jupyter/instances/y/proxy/",
		AllowOrigin: "https://x.example",
	})

	mustContain(t, got, "command -v jupyter")
	mustContain(t, got, "conda create -y -p ./jupyter-env")
	mustContain(t, got, "python3 -m venv ./jupyter-env")
	// Pin the pip-install command + the LSP package so a future edit
	// can't silently drop completion/hover from the on-the-fly env.
	mustContain(t, got, "pip install --quiet --disable-pip-version-check")
	mustContain(t, got, "jupyterlab")
	mustContain(t, got, "'python-lsp-server[all]'")
	mustContain(t, got, "exec jupyter lab")
}

// TestBuildJupyterTunnelURL covers the scheme + host derivation.
func TestBuildJupyterTunnelURL(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		host    string
		tls     bool
		want    string
	}{
		{name: "from-base-https", baseURL: "https://api.example.com", host: "ignored:0", want: "wss://api.example.com/api/v1/jupyter/instances/x/tunnel"},
		{name: "from-base-http", baseURL: "http://api.example.com", host: "ignored:0", want: "ws://api.example.com/api/v1/jupyter/instances/x/tunnel"},
		{name: "fallback-host", baseURL: "", host: "127.0.0.1:8080", want: "ws://127.0.0.1:8080/api/v1/jupyter/instances/x/tunnel"},
		{name: "fallback-tls", baseURL: "", host: "x.example", tls: true, want: "wss://x.example/api/v1/jupyter/instances/x/tunnel"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://"+tc.host+"/", nil)
			r.Host = tc.host
			if tc.tls {
				// httptest.NewRequest doesn't set TLS automatically; fake it.
				r.TLS = &tls.ConnectionState{}
			}
			got := buildJupyterTunnelURL(r, "x", tc.baseURL)
			if got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("submit file missing %q\n--- full ---\n%s\n--- end ---", needle, haystack)
	}
}
