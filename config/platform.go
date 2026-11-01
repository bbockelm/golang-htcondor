package config

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// The platform macros -- ARCH, OPSYS and the family around them -- name the
// machine to the rest of the pool. A startd advertises them, a job's
// Requirements is pinned to them by condor_submit, and a config file can
// reference any of them, so each one has to carry the value HTCondor's own
// sysapi would compute. A name HTCondor does not use expands to nothing in a
// config file, and a VALUE no machine advertises makes a job match nothing at
// all.
//
// This mirrors init_arch and the platform block of real_config
// (condor_sysapi/arch.cpp, condor_utils/condor_config.cpp). Where sysapi's
// answer depends on files or a syscall, this reads the same ones.

// platformInfo is the set of platform macros, named after the macros rather
// than after sysapi's accessors.
type platformInfo struct {
	Arch     string // ARCH
	Opsys    string // OPSYS
	Legacy   string // OPSYSLEGACY
	Name     string // OPSYSNAME
	Short    string // OPSYSSHORTNAME
	Long     string // OPSYSLONGNAME
	MajorVer int    // OPSYSMAJORVER
	Ver      int    // OPSYSVER
	AndVer   string // OPSYSANDVER
}

// detectPlatform fills in the family for the running machine.
//
// Everything below the first two is derived from the OS's own version string,
// which is why Long is computed first: sysapi runs the version helpers over
// the LONG NAME, not over a bare version number, and the major version it
// reports comes from the first run of digits in it.
func detectPlatform() platformInfo {
	p := platformInfo{
		Arch:  htcondorArch(unameMachine(runtime.GOARCH)),
		Opsys: goOSToHTCondorOS(runtime.GOOS),
	}
	p.Legacy = opsysLegacy(runtime.GOOS, p.Opsys)

	switch runtime.GOOS {
	case "darwin":
		// "macOS <major>.<minor>", as sysapi_get_darwin_info formats it.
		major, minor, ok := darwinVersion()
		if !ok {
			return p
		}
		p.Long = fmt.Sprintf("macOS %d.%d", major, minor)
		p.Short = "macOS"
		p.Name = darwinCodename(major, minor)
		p.MajorVer = major
		p.Ver = translateOpsysVersion(p.Long)
	case "linux":
		long, ok := linuxLongName()
		if !ok {
			return p
		}
		p.Long = long
		p.Name = linuxDistroName(long)
		// On Linux the short name IS the distro name; OPSYS stays "LINUX".
		p.Short = p.Name
		p.MajorVer = findMajorVersion(long)
		p.Ver = translateOpsysVersion(long)
	default:
		return p
	}

	if p.Name != "" && p.MajorVer > 0 {
		// sysapi_find_opsys_versioned is "%s%d" over the name and the major
		// version: AlmaLinux9, macOS27.
		p.AndVer = fmt.Sprintf("%s%d", opsysVersionedName(runtime.GOOS, p), p.MajorVer)
	}
	return p
}

// opsysVersionedName is the name OPSYSANDVER is built from, which is not the
// same accessor on every platform: the Darwin branch of init_arch passes
// opsys_short_name and the Linux branch passes opsys_name. They agree on Linux,
// where the short name is a copy of the name, and differ nowhere else that
// matters -- but the distinction is sysapi's, so it is kept.
func opsysVersionedName(goos string, p platformInfo) string {
	if goos == "darwin" {
		return p.Short
	}
	return p.Name
}

// opsysLegacy is OPSYSLEGACY: the name HTCondor used before OPSYS carried the
// friendlier one. It is its own macro because machines still advertise it, and
// it is NOT interchangeable with OPSYS -- reporting OSX as OPSYS, which this
// package used to do, describes no machine a modern pool has.
func opsysLegacy(goos, opsys string) string {
	switch goos {
	case "darwin":
		return "OSX"
	case "linux":
		return "LINUX"
	case "windows":
		// sysapi sets opsys_legacy from the Windows version (WINNT61 and
		// friends), which this package does not compute; OPSYS is the honest
		// answer rather than a made-up one.
		return opsys
	default:
		// The generic Unix branch uppercases the OS name for both.
		return strings.ToUpper(opsys)
	}
}

// translateOpsysVersion is sysapi_translate_opsys_version: the first run of
// digits in the string is the major version, and up to two digits after a
// following "." are the minor, giving major*100 + minor. "macOS 27.0" is 2700
// and "AlmaLinux release 9.5" is 905.
func translateOpsysVersion(info string) int {
	if info == "" || info == "Unknown" {
		return 0
	}
	i := 0
	for i < len(info) && (info[i] < '0' || info[i] > '9') {
		i++
	}
	major := 0
	for i < len(info) && info[i] >= '0' && info[i] <= '9' {
		major = major*10 + int(info[i]-'0')
		i++
	}
	minor := 0
	if i < len(info) && info[i] == '.' {
		i++
		for digits := 0; digits < 2 && i < len(info) && info[i] >= '0' && info[i] <= '9'; digits++ {
			minor = minor*10 + int(info[i]-'0')
			i++
		}
	}
	return major*100 + minor
}

// findMajorVersion is sysapi_find_major_version: the first run of digits,
// without the minor version translateOpsysVersion folds in.
func findMajorVersion(info string) int {
	if info == "" || info == "Unknown" {
		return 0
	}
	i := 0
	for i < len(info) && (info[i] < '0' || info[i] > '9') {
		i++
	}
	major := 0
	for i < len(info) && info[i] >= '0' && info[i] <= '9' {
		major = major*10 + int(info[i]-'0')
		i++
	}
	return major
}

// linuxIssueFiles are the files sysapi_get_linux_info reads, in its order.
// Note that /etc/os-release is NOT among them: it is only the fallback below,
// and reading it first -- as this package used to -- gives a different answer
// on any machine whose /etc/issue names a distro.
var linuxIssueFiles = []string{
	"/etc/issue",
	"/etc/redhat-release",
	"/etc/system-release",
	"/etc/issue.net",
}

// linuxLongName is sysapi_get_linux_info: the first line of the first issue
// file that names a distro this version recognizes, falling back to
// /etc/os-release's PRETTY_NAME.
//
// The "names a distro" test is the subtle part: a file whose first line does
// not match the distro table is SKIPPED rather than used, because /etc/issue
// on some machines is a banner with no version in it at all.
func linuxLongName() (string, bool) {
	for _, path := range linuxIssueFiles {
		line, ok := firstLine(path)
		if !ok {
			continue
		}
		line = trimIssueLine(line)
		if line == "" {
			continue
		}
		if linuxDistroName(line) != "LINUX" {
			return line, true
		}
	}
	if pretty, ok := osReleasePrettyName(); ok {
		return pretty, true
	}
	return "", false
}

// firstLine reads the first line of a file.
func firstLine(path string) (string, bool) {
	data, err := os.ReadFile(path) //nolint:gosec // a fixed list of system files
	if err != nil {
		return "", false
	}
	line, _, _ := strings.Cut(string(data), "\n")
	return line, true
}

// trimIssueLine trims trailing whitespace and the escape pairs Debian and
// Ubuntu leave at the end of /etc/issue -- a literal `\n` or `\l`, which look
// like a bug in their file and are stripped rather than reported as part of
// the OS name.
func trimIssueLine(line string) string {
	line = strings.TrimRight(line, " \t\r\n\v\f")
	for len(line) > 2 && line[len(line)-2] == '\\' &&
		(line[len(line)-1] == 'n' || line[len(line)-1] == 'l') {
		line = strings.TrimRight(line[:len(line)-2], " \t\r\n\v\f")
	}
	return line
}

// osReleasePrettyName reads PRETTY_NAME out of /etc/os-release, taking what is
// inside the first pair of double quotes as sysapi does.
func osReleasePrettyName() (string, bool) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "PRETTY_NAME") {
			continue
		}
		_, rest, found := strings.Cut(line, `"`)
		if !found {
			continue
		}
		if value, _, closed := strings.Cut(rest, `"`); closed {
			return value, true
		}
	}
	return "", false
}

// linuxDistroName is sysapi_find_linux_name. The ORDER matters and is kept:
// "opensuse" has to be tested before "suse", and the Scientific Linux variants
// before plain Scientific, or a CERN machine reports itself as the wrong one.
// A line that matches nothing is "LINUX", which is also the signal to
// linuxLongName that the file it came from named no distro.
func linuxDistroName(info string) string {
	s := strings.ToLower(info)
	switch {
	case strings.Contains(s, "red") && strings.Contains(s, "hat"):
		return "RedHat"
	case strings.Contains(s, "fedora"):
		return "Fedora"
	case strings.Contains(s, "ubuntu"):
		return "Ubuntu"
	case strings.Contains(s, "debian"):
		return "Debian"
	case strings.Contains(s, "scientific") && strings.Contains(s, "cern"):
		return "SLCern"
	case strings.Contains(s, "scientific") && strings.Contains(s, "slf"):
		return "SLFermi"
	case strings.Contains(s, "scientific"):
		return "SL"
	case strings.Contains(s, "centos"):
		return "CentOS"
	case strings.Contains(s, "rocky"):
		return "Rocky"
	case strings.Contains(s, "almalinux"):
		return "AlmaLinux"
	case strings.Contains(s, "amazon linux"):
		return "AmazonLinux"
	case strings.Contains(s, "opensuse"):
		return "openSUSE"
	case strings.Contains(s, "suse"):
		return "SUSE"
	default:
		return "LINUX"
	}
}

// darwinCodename is the OPSYSNAME table of sysapi_get_darwin_info. A release
// newer than the table is "Unknown", which is what HTCondor reports too
// rather than guessing.
func darwinCodename(major, minor int) string {
	switch {
	case major == 26:
		return "Tahoe"
	case major == 15:
		return "Sequoia"
	case major == 14:
		return "Sonoma"
	case major == 13:
		return "Ventura"
	case major == 12:
		return "Monterey"
	case major == 11:
		return "BigSur"
	case major == 10 && minor == 15:
		return "Catalina"
	case major == 10 && minor == 14:
		return "Mojave"
	case major == 10 && minor == 13:
		return "HighSierra"
	default:
		return "Unknown"
	}
}

// utsname is the subset of uname's output HTCondor publishes.
type utsname struct {
	Sysname  string
	Nodename string
	Release  string
	Version  string
	Machine  string
}
