package config

import (
	"os"
	"path/filepath"
	"testing"
)

// translateOpsysVersion folds the minor version in at two digits, which is
// what makes OPSYSVER 2700 for macOS 27.0 rather than 27.
func TestTranslateOpsysVersion(t *testing.T) {
	cases := map[string]int{
		"macOS 27.0":                      2700,
		"macOS 10.15":                     1015,
		"AlmaLinux release 9.5 (Teal)":    905,
		"Rocky Linux release 8.10 (Obs)":  810,
		"Ubuntu 24.04.1 LTS":              2404,
		"Red Hat Enterprise Linux 9":      900,
		"Unknown":                         0,
		"":                                0,
		"no digits here":                  0,
		"Fedora release 41 (Forty One)":   4100,
		"Scientific Linux release 7.9999": 799,
	}
	for in, want := range cases {
		if got := translateOpsysVersion(in); got != want {
			t.Errorf("translateOpsysVersion(%q) = %d, want %d", in, got, want)
		}
	}
}

// findMajorVersion stops at the first run of digits, with no minor part.
func TestFindMajorVersion(t *testing.T) {
	cases := map[string]int{
		"macOS 27.0":                   27,
		"AlmaLinux release 9.5 (Teal)": 9,
		"Ubuntu 24.04.1 LTS":           24,
		"Unknown":                      0,
		"":                             0,
	}
	for in, want := range cases {
		if got := findMajorVersion(in); got != want {
			t.Errorf("findMajorVersion(%q) = %d, want %d", in, got, want)
		}
	}
}

// The distro table is ordered, and two of the orderings are load-bearing:
// openSUSE contains "suse", and the Scientific Linux variants contain
// "scientific". Testing the specific cases is the only way to notice if the
// branches are ever reordered.
func TestLinuxDistroName(t *testing.T) {
	cases := map[string]string{
		"Red Hat Enterprise Linux release 9.4 (Plow)": "RedHat",
		"Fedora release 41 (Forty One)":               "Fedora",
		"Ubuntu 24.04.1 LTS":                          "Ubuntu",
		"Debian GNU/Linux 12 (bookworm)":              "Debian",
		"Scientific Linux CERN SLC release 6.10":      "SLCern",
		"Scientific Linux SLF release 6.10":           "SLFermi",
		"Scientific Linux release 7.9 (Nitrogen)":     "SL",
		"CentOS Stream release 9":                     "CentOS",
		"Rocky Linux release 9.4 (Blue Onyx)":         "Rocky",
		"AlmaLinux release 9.5 (Teal Serval)":         "AlmaLinux",
		"Amazon Linux release 2023":                   "AmazonLinux",
		"openSUSE Leap 15.6":                          "openSUSE",
		"SUSE Linux Enterprise Server 15 SP6":         "SUSE",
		"Arch Linux \\r (\\l)":                        "LINUX",
		"":                                            "LINUX",
	}
	for in, want := range cases {
		if got := linuxDistroName(in); got != want {
			t.Errorf("linuxDistroName(%q) = %q, want %q", in, got, want)
		}
	}
}

// Debian and Ubuntu leave a literal \n or \l at the end of /etc/issue, which
// would otherwise be reported as part of the OS name.
func TestTrimIssueLine(t *testing.T) {
	cases := map[string]string{
		"Ubuntu 24.04.1 LTS \\n \\l":   "Ubuntu 24.04.1 LTS",
		"Debian GNU/Linux 12 \\n \\l ": "Debian GNU/Linux 12",
		"AlmaLinux release 9.5\n":      "AlmaLinux release 9.5",
		"Rocky Linux release 9.4   ":   "Rocky Linux release 9.4",
		"plain":                        "plain",
	}
	for in, want := range cases {
		if got := trimIssueLine(in); got != want {
			t.Errorf("trimIssueLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// A file whose first line names no distro is SKIPPED rather than used, because
// /etc/issue on some machines is a login banner with no version in it. Reading
// the first file unconditionally would report that banner as the OS.
func TestLinuxLongNameSkipsFilesNamingNoDistro(t *testing.T) {
	dir := t.TempDir()
	banner := filepath.Join(dir, "issue")
	release := filepath.Join(dir, "redhat-release")
	if err := os.WriteFile(banner, []byte("Authorized users only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release, []byte("AlmaLinux release 9.5 (Teal Serval)\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	saved := linuxIssueFiles
	t.Cleanup(func() { linuxIssueFiles = saved })
	linuxIssueFiles = []string{banner, release}

	got, ok := linuxLongName()
	if !ok || got != "AlmaLinux release 9.5 (Teal Serval)" {
		t.Errorf("linuxLongName() = %q, %v; want the release file's line", got, ok)
	}
}

// The first file that does name a distro wins, so the order in
// linuxIssueFiles is the order HTCondor reads them in.
func TestLinuxLongNameTakesTheFirstFileNamingADistro(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "issue")
	second := filepath.Join(dir, "system-release")
	if err := os.WriteFile(first, []byte("Ubuntu 24.04.1 LTS \\n \\l\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("Rocky Linux release 9.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	saved := linuxIssueFiles
	t.Cleanup(func() { linuxIssueFiles = saved })
	linuxIssueFiles = []string{first, second}

	got, ok := linuxLongName()
	if !ok || got != "Ubuntu 24.04.1 LTS" {
		t.Errorf("linuxLongName() = %q, %v; want the first file's line, trimmed", got, ok)
	}
}

// OPSYSLEGACY is not interchangeable with OPSYS, which is the whole point of
// the bug this family was fixed for.
func TestOpsysLegacyIsNotOpsys(t *testing.T) {
	if got := opsysLegacy("darwin", "macOS"); got != "OSX" {
		t.Errorf("opsysLegacy(darwin) = %q, want OSX", got)
	}
	if got := opsysLegacy("linux", "LINUX"); got != "LINUX" {
		t.Errorf("opsysLegacy(linux) = %q, want LINUX", got)
	}
}

// ARCH follows sysapi_condor_arch, which renames a handful of uname machine
// names and passes everything else -- arm64 included -- through unchanged.
func TestHTCondorArch(t *testing.T) {
	cases := map[string]string{
		"x86_64":  "X86_64",
		"amd64":   "X86_64",
		"i386":    "INTEL",
		"i686":    "INTEL",
		"ia64":    "IA64",
		"ppc64":   "PPC64",
		"ppc":     "PPC",
		"arm64":   "arm64",
		"aarch64": "aarch64",
		"ppc64le": "ppc64le",
		"s390x":   "s390x",
	}
	for in, want := range cases {
		if got := htcondorArch(in); got != want {
			t.Errorf("htcondorArch(%q) = %q, want %q", in, got, want)
		}
	}
}
