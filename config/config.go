// Package config implements HTCondor configuration file parsing and management.
//
// The HTCondor configuration language supports:
// - Variable definitions with macro expansion
// - Include directives for importing other config files
// - Conditional evaluation (if/elif/else/endif)
// - Function macros ($ENV, $INT, $SUBSTR, etc.)
// - Subsystem-specific variables (e.g., MASTER.VARIABLE)
// - Comment and line continuation support
//
// Example usage:
//
//	cfg, err := config.New()
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	value, ok := cfg.Get("COLLECTOR_HOST")
//	if !ok {
//	    log.Fatal("COLLECTOR_HOST not defined")
//	}
package config

//go:generate go run ../param/generate.go

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// ConfigOptions contains configuration parameters for creating a Config
//
//nolint:revive // Name is consistent with HTCondor conventions
type ConfigOptions struct {
	// LocalName is the local name for this HTCondor instance (e.g., "manager", "worker")
	// This affects variable prefix resolution
	LocalName string

	// Subsystem is the HTCondor subsystem (e.g., "MASTER", "SCHEDD", "STARTD")
	// This affects subsystem-specific variable resolution (e.g., MASTER.VARIABLE)
	Subsystem string

	// HTCondorCompat restricts the parser to HTCondor's exact grammar,
	// disabling Go-only extensions so a config behaves the same here as under
	// condor_config. Currently this gates the richer `if` conditions: HTCondor
	// accepts only a bare boolean, `defined X`, or `version <op> x`, whereas Go
	// also allows numeric/string comparisons and && / ||. Default (false) keeps
	// the extensions; the differential config fuzzer sets this so it compares Go
	// against HTCondor faithfully. (Other extensions — $DIRNAME/$BASENAME,
	// nested-macro re-expansion — remain on even in compat for now and are
	// tracked as intentional divergences.)
	HTCondorCompat bool

	// SkipDefaults, when true, suppresses initBuiltins(): no param_info
	// defaults, no param overrides, no time constants (SECOND/MINUTE/...), and
	// no auto-detected macros (FULL_HOSTNAME, DETECTED_CPUS, TILDE, ...). The
	// resulting Config contains only what the parsed source defines. This
	// mirrors HTCondor's Parse_config_string on a fresh MACRO_SET with a NULL
	// defaults table, which is what the differential config fuzzer compares
	// against; it is also useful for parsing standalone snippets whose meaning
	// must not depend on host state.
	SkipDefaults bool
}

// Config represents an HTCondor configuration with key-value pairs
type Config struct {
	values map[string]string
	// Track macro evaluation depth to detect loops
	evaluating map[string]bool
	// Track included files to prevent cycles
	includedFiles map[string]bool
	// Configuration options
	options ConfigOptions
	// Track if we're executing inside a metaknob template
	inMetaknob bool
}

// New creates a new Config from the runtime environment
func New() (*Config, error) {
	return NewWithOptions(ConfigOptions{})
}

// NewEmpty creates a new empty Config without loading from environment
// This is useful for submit files where we want to parse explicitly
func NewEmpty() *Config {
	cfg := &Config{
		values:        make(map[string]string),
		evaluating:    make(map[string]bool),
		includedFiles: make(map[string]bool),
	}

	// Initialize with built-in macros and param defaults
	cfg.initBuiltins()

	return cfg
}

// Options returns the options this Config was constructed with. It lets a caller reload
// (e.g. on condor_reconfig) while preserving subsystem and local-name prefix resolution —
// a bare config.New() reload would drop them and stop resolving <SUBSYS>.PARAM overrides.
func (c *Config) Options() ConfigOptions { return c.options }

// NewWithOptions creates a new Config with specified options.
func NewWithOptions(opts ConfigOptions) (*Config, error) {
	cfg := &Config{
		values:        make(map[string]string),
		evaluating:    make(map[string]bool),
		includedFiles: make(map[string]bool),
		options:       opts,
	}

	// Initialize with built-in macros and param defaults
	if !opts.SkipDefaults {
		cfg.initBuiltins()
	}

	// Load from environment
	return cfg, cfg.LoadFromEnvironment()
}

// NewFromReader creates a Config from an io.Reader using the parser
func NewFromReader(r io.Reader) (*Config, error) {
	return NewFromReaderWithOptions(r, ConfigOptions{})
}

// NewFromReaderWithOptions creates a Config from an io.Reader with specified options
func NewFromReaderWithOptions(r io.Reader, opts ConfigOptions) (*Config, error) {
	cfg := &Config{
		values:        make(map[string]string),
		evaluating:    make(map[string]bool),
		includedFiles: make(map[string]bool),
		options:       opts,
	}

	// Initialize built-in macros and param defaults
	if !opts.SkipDefaults {
		cfg.initBuiltins()
	}

	// Parse and execute using the new parser
	if err := cfg.parseAndExecute(r); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Get retrieves a configuration value, honoring HTCondor's subsystem and
// local-name prefix precedence. For a Config created with a Subsystem and/or
// LocalName, a more specific definition overrides the bare parameter, most
// specific first:
//
//	<SUBSYS>.<LOCALNAME>.<KEY>   (e.g. COLLECTOR.HTCVIEW.CONDOR_VIEW_HOST)
//	<LOCALNAME>.<KEY>            (e.g. HTCVIEW.CONDOR_VIEW_HOST)
//	<SUBSYS>.<KEY>               (e.g. COLLECTOR.CONDOR_VIEW_HOST)
//	<KEY>                        (the bare parameter)
//
// This is what lets two daemons of the same subsystem run under one
// condor_master with distinct config -- e.g. the stock C++ condor_collector and
// an htc-collector view host (started with -local-name HTCVIEW) taking different
// COLLECTOR_LOG, COLLECTOR_ADDRESS_FILE, and CONDOR_VIEW_HOST values.
func (c *Config) Get(key string) (string, bool) {
	// Check for macro expansion
	if strings.HasPrefix(key, "$(") && strings.HasSuffix(key, ")") {
		key = key[2 : len(key)-1]
	}

	key = c.scopedLookupKey(key)

	val, ok := c.values[key]
	if !ok {
		return "", false
	}

	// Expand macros and function macros in the value
	expanded, err := c.expandMacrosWithFunctions(val)
	if err != nil {
		return val, true // Return unexpanded on error
	}

	return expanded, true
}

// scopedLookupKey returns the most specific map key that exists for the bare
// parameter name, applying the Config's subsystem/local-name prefixes in
// HTCondor precedence order (see Get). It leaves an already-qualified key (one
// containing '.') untouched so an explicit dotted lookup is not re-prefixed, and
// returns key unchanged when neither subsystem nor local name is set or no scoped
// definition exists.
func (c *Config) scopedLookupKey(key string) string {
	subsys, local := c.options.Subsystem, c.options.LocalName
	if (subsys == "" && local == "") || strings.ContainsRune(key, '.') {
		return key
	}
	// Most specific first; only override when a scoped definition actually exists.
	if subsys != "" && local != "" {
		if _, ok := c.values[subsys+"."+local+"."+key]; ok {
			return subsys + "." + local + "." + key
		}
	}
	if local != "" {
		if _, ok := c.values[local+"."+key]; ok {
			return local + "." + key
		}
	}
	if subsys != "" {
		if _, ok := c.values[subsys+"."+key]; ok {
			return subsys + "." + key
		}
	}
	return key
}

// Set sets a configuration value
func (c *Config) Set(key, value string) {
	// Check if this is a self-referential definition
	if strings.Contains(value, "$("+key+")") {
		// Expand the self-reference immediately
		if oldVal, ok := c.values[key]; ok {
			value = strings.ReplaceAll(value, "$("+key+")", oldVal)
		} else {
			// First definition, just remove the self-reference
			value = strings.ReplaceAll(value, "$("+key+")", "")
		}
	}

	c.values[key] = value
}

// Keys returns all configuration keys
func (c *Config) Keys() []string {
	keys := make([]string, 0, len(c.values))
	for k := range c.values {
		keys = append(keys, k)
	}
	return keys
}

// initBuiltins initializes built-in predefined macros
func (c *Config) initBuiltins() {
	// First, load defaults from param_info.in (unexpanded)
	// These act as the base defaults that can be overridden
	for _, pd := range paramDefaults {
		// Use Win32Default on Windows if available, otherwise use Default
		defaultVal := pd.Default
		if pd.Win32Default != "" && isWindows() {
			defaultVal = pd.Win32Default
		}
		// Set the value (unexpanded - will be expanded on Get())
		c.values[pd.Name] = defaultVal
	}

	// Apply hand-curated overrides from param_overrides.go. These
	// patch entries whose generated defaults have drifted from
	// HTCondor's actual built-in defaults — see param_overrides.go for
	// the rationale on each one. Applied AFTER paramDefaults so they
	// win, BEFORE any CONDOR_CONFIG file load so user values still win
	// over them.
	for _, po := range paramOverrides {
		c.values[po.Name] = po.Default
	}

	// Time constants (these override param defaults)
	c.Set("SECOND", "1")
	c.Set("MINUTE", "60")
	c.Set("HOUR", "3600")
	c.Set("DAY", "86400")
	c.Set("WEEK", "604800")

	// Auto-detected values
	hostname, _ := os.Hostname()
	c.Set("HOSTNAME", strings.Split(hostname, ".")[0])
	c.Set("FULL_HOSTNAME", hostname)

	// IP address detection
	ipv4Addr, ipv6Addr, ipAddr := detectIPAddresses()
	if ipv4Addr != "" {
		c.Set("IPV4_ADDRESS", ipv4Addr)
	}
	if ipv6Addr != "" {
		c.Set("IPV6_ADDRESS", ipv6Addr)
	}
	if ipAddr != "" {
		c.Set("IP_ADDRESS", ipAddr)
		// Set IP_ADDRESS_IS_V6 based on whether IP_ADDRESS is IPv6
		isV6 := "false"
		if strings.Contains(ipAddr, ":") {
			isV6 = "true"
		}
		c.Set("IP_ADDRESS_IS_V6", isV6)
	}

	// User and directory information
	if tilde := getCondorUserHomeDir(); tilde != "" {
		c.Set("TILDE", tilde)
	}
	if username := getCurrentUsername(); username != "" {
		c.Set("USERNAME", username)
	}

	// Config root directory
	c.Set("CONFIG_ROOT", getConfigRoot())

	// CPU and memory detection (Priority 2)
	logicalCPUs, physicalCPUs := detectCPUs()
	c.Set("DETECTED_CPUS", fmt.Sprintf("%d", logicalCPUs))
	c.Set("DETECTED_CORES", fmt.Sprintf("%d", logicalCPUs)) // Alias for DETECTED_CPUS
	c.Set("DETECTED_PHYSICAL_CPUS", fmt.Sprintf("%d", physicalCPUs))

	memory := detectMemory()
	if memory > 0 {
		c.Set("DETECTED_MEMORY", fmt.Sprintf("%d", memory))
	}

	// Architecture and OS detection
	c.Set("ARCH", goArchToHTCondorArch(runtime.GOARCH))
	c.Set("OPSYS", goOSToHTCondorOS(runtime.GOOS))

	osVersion := detectOSVersion()
	if osVersion != "" {
		c.Set("OPSYS_VER", osVersion)
		c.Set("OPSYS_AND_VER", goOSToHTCondorOS(runtime.GOOS)+osVersion)
	}

	// UNAME values
	unameArch, unameOpsys := getUnameValues()
	c.Set("UNAME_ARCH", unameArch)
	c.Set("UNAME_OPSYS", unameOpsys)

	// Process information
	c.Set("PID", fmt.Sprintf("%d", os.Getpid()))
	c.Set("PPID", fmt.Sprintf("%d", os.Getppid()))

	// CPU limit detection (uses DETECTED_CPUS set above)
	limit := getDetectedCPUsLimit(logicalCPUs)
	c.Set("DETECTED_CPUS_LIMIT", fmt.Sprintf("%d", limit))

	// Subsystem - use configured subsystem or default to TOOL
	if c.options.Subsystem != "" {
		c.Set("SUBSYSTEM", c.options.Subsystem)
	} else {
		c.Set("SUBSYSTEM", "TOOL")
	}

	// Local name if specified
	if c.options.LocalName != "" {
		c.Set("LOCAL_NAME", c.options.LocalName)
	}
}

// isWindows checks if running on Windows
func isWindows() bool {
	return os.PathSeparator == '\\'
}

// detectIPAddresses detects IP addresses from network interfaces
// Returns: ipv4Address, ipv6Address, mostPublicIP
func detectIPAddresses() (string, string, string) {
	// Get all network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", ""
	}

	// Sort interfaces alphabetically by name
	sort.Slice(interfaces, func(i, j int) bool {
		return interfaces[i].Name < interfaces[j].Name
	})

	var ipv4Addresses []string
	var ipv6Addresses []string

	// Categorize addresses by priority
	type addressWithPriority struct {
		addr     string
		priority int // 0=best (non-link-local, non-loopback), 1=link-local, 2=loopback
	}
	var ipv4WithPrio []addressWithPriority
	var ipv6WithPrio []addressWithPriority

	for _, iface := range interfaces {
		// Skip down interfaces
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			default:
				continue
			}

			if ip == nil {
				continue
			}

			ipStr := ip.String()
			priority := 0

			// Determine priority
			switch {
			case ip.IsLoopback():
				priority = 2 // Lowest priority
			case ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast():
				priority = 1 // Medium priority
			default:
				priority = 0 // Highest priority
			}

			// Categorize by IP version
			if ip.To4() != nil {
				//nolint:staticcheck // SA4010: False positive - slice is sorted and used later
				ipv4Addresses = append(ipv4Addresses, ipStr)
				ipv4WithPrio = append(ipv4WithPrio, addressWithPriority{ipStr, priority})
			} else if ip.To16() != nil {
				//nolint:staticcheck // SA4010: False positive - slice is sorted and used later
				ipv6Addresses = append(ipv6Addresses, ipStr)
				ipv6WithPrio = append(ipv6WithPrio, addressWithPriority{ipStr, priority})
			}
		}
	} // Sort by priority (lowest priority value first)
	sort.Slice(ipv4WithPrio, func(i, j int) bool {
		if ipv4WithPrio[i].priority != ipv4WithPrio[j].priority {
			return ipv4WithPrio[i].priority < ipv4WithPrio[j].priority
		}
		return ipv4WithPrio[i].addr < ipv4WithPrio[j].addr
	})
	sort.Slice(ipv6WithPrio, func(i, j int) bool {
		if ipv6WithPrio[i].priority != ipv6WithPrio[j].priority {
			return ipv6WithPrio[i].priority < ipv6WithPrio[j].priority
		}
		return ipv6WithPrio[i].addr < ipv6WithPrio[j].addr
	})

	// Get the best addresses
	var ipv4Best, ipv6Best, mostPublic string

	if len(ipv4WithPrio) > 0 {
		ipv4Best = ipv4WithPrio[0].addr
	}
	if len(ipv6WithPrio) > 0 {
		ipv6Best = ipv6WithPrio[0].addr
	}

	// Most public is the best IPv4, or if none, the best IPv6
	if ipv4Best != "" {
		mostPublic = ipv4Best
	} else if ipv6Best != "" {
		mostPublic = ipv6Best
	}

	return ipv4Best, ipv6Best, mostPublic
}

// getCondorUserHomeDir gets the home directory of the 'condor' user
func getCondorUserHomeDir() string {
	u, err := user.Lookup("condor")
	if err != nil {
		// If condor user doesn't exist, return empty string
		return ""
	}
	return u.HomeDir
}

// getCurrentUsername gets the current user's username
func getCurrentUsername() string {
	u, err := user.Current()
	if err != nil {
		return ""
	}
	return u.Username
}

// getConfigRoot gets the directory containing the main config file
func getConfigRoot() string {
	// Check CONDOR_CONFIG environment variable
	condorConfig := os.Getenv("CONDOR_CONFIG")
	if condorConfig != "" {
		// Return the parent directory
		return filepath.Dir(condorConfig)
	}

	// Default based on OS
	if isWindows() {
		return "C:\\Condor"
	}
	return "/etc/condor"
}

// getDetectedCPUsLimit returns the minimum of DETECTED_CPUS and environment limits
func getDetectedCPUsLimit(detectedCPUs int) int {
	limit := detectedCPUs

	// Check OMP_THREAD_LIMIT
	if ompLimit := os.Getenv("OMP_THREAD_LIMIT"); ompLimit != "" {
		if val, err := strconv.Atoi(ompLimit); err == nil && val > 0 && val < limit {
			limit = val
		}
	}

	// Check SLURM_CPUS_ON_NODE
	if slurmLimit := os.Getenv("SLURM_CPUS_ON_NODE"); slurmLimit != "" {
		if val, err := strconv.Atoi(slurmLimit); err == nil && val > 0 && val < limit {
			limit = val
		}
	}

	return limit
}

// detectCPUs detects CPU counts
// Returns: logicalCPUs (with HT), physicalCPUs (without HT)
func detectCPUs() (int, int) {
	// Try to read /proc/cpuinfo on Linux
	if runtime.GOOS == "linux" {
		if logical, physical, ok := detectCPUsLinux(); ok {
			return logical, physical
		}
	}

	// Fallback to runtime.NumCPU()
	numCPU := runtime.NumCPU()
	return numCPU, numCPU
}

// detectCPUsLinux parses /proc/cpuinfo to detect CPU counts
func detectCPUsLinux() (int, int, bool) {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0, 0, false
	}

	// Count unique (physical id, core id) pairs for physical cores
	// Count processor entries for logical CPUs
	type physCore struct {
		physicalID int
		coreID     int
	}
	physicalCores := make(map[physCore]bool)
	logicalCPUs := 0
	currentPhysID := -1
	currentCoreID := -1

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "processor"):
			logicalCPUs++
			// Reset for next processor
			currentPhysID = -1
			currentCoreID = -1
		case strings.HasPrefix(line, "physical id"):
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if id, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					currentPhysID = id
				}
			}
		case strings.HasPrefix(line, "core id"):
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if id, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
					currentCoreID = id
				}
			}
		}

		// If we have both IDs, record this physical core
		if currentPhysID >= 0 && currentCoreID >= 0 {
			physicalCores[physCore{currentPhysID, currentCoreID}] = true
		}
	} // If we didn't find physical/core IDs, assume no hyperthreading
	physCount := len(physicalCores)
	if physCount == 0 {
		physCount = logicalCPUs
	}

	if logicalCPUs > 0 {
		return logicalCPUs, physCount, true
	}
	return 0, 0, false
}

// detectMemory detects system memory in MiB
func detectMemory() int {
	// Try to read /proc/meminfo on Linux
	if runtime.GOOS == "linux" {
		if mem, ok := detectMemoryLinux(); ok {
			return mem
		}
	}

	// Fallback to syscall for other platforms
	return detectMemorySyscall()
}

// detectMemoryLinux parses /proc/meminfo
func detectMemoryLinux() (int, bool) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					// Convert KB to MiB
					return int(kb / 1024), true
				}
			}
		}
	}
	return 0, false
}

// detectMemorySyscall uses syscall to detect memory
func detectMemorySyscall() int {
	// Platform-specific syscall
	if runtime.GOOS == "darwin" || runtime.GOOS == "freebsd" {
		// Use sysctl for BSD-like systems
		return detectMemorySysctl()
	}
	// Default fallback
	return 0
}

// detectMemorySysctl uses sysctl to get memory on BSD-like systems
func detectMemorySysctl() int {
	cmd := exec.CommandContext(context.Background(), "sysctl", "-n", "hw.memsize")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	bytes, err := strconv.ParseInt(strings.TrimSpace(string(output)), 10, 64)
	if err != nil {
		return 0
	}
	// Convert bytes to MiB
	return int(bytes / (1024 * 1024))
}

// goArchToHTCondorArch converts Go's GOARCH to HTCondor ARCH format
func goArchToHTCondorArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "X86_64"
	case "386":
		return "INTEL"
	case "arm64":
		return "ARM64"
	case "arm":
		return "ARM"
	case "ppc64", "ppc64le":
		return "PPC64"
	case "s390x":
		return "S390X"
	default:
		// Return uppercase version as fallback
		return strings.ToUpper(goarch)
	}
}

// goOSToHTCondorOS converts Go's GOOS to HTCondor OPSYS format
func goOSToHTCondorOS(goos string) string {
	switch goos {
	case "linux":
		return "LINUX"
	case "darwin":
		return "OSX"
	case "windows":
		return "WINDOWS"
	case "freebsd":
		return "FREEBSD"
	case "openbsd":
		return "OPENBSD"
	case "netbsd":
		return "NETBSD"
	case "solaris":
		return "SOLARIS"
	default:
		return strings.ToUpper(goos)
	}
}

// detectOSVersion returns the major OS version
func detectOSVersion() string {
	switch runtime.GOOS {
	case "linux":
		return detectLinuxVersion()
	case "darwin":
		return detectDarwinVersion()
	case "windows":
		return detectWindowsVersion()
	default:
		return ""
	}
}

// detectLinuxVersion detects Linux version from /etc/os-release
func detectLinuxVersion() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "VERSION_ID=") {
			version := strings.TrimPrefix(line, "VERSION_ID=")
			version = strings.Trim(version, "\"")
			// Return major version only
			if idx := strings.Index(version, "."); idx > 0 {
				return version[:idx]
			}
			return version
		}
	}
	return ""
}

// detectDarwinVersion detects macOS version
func detectDarwinVersion() string {
	cmd := exec.CommandContext(context.Background(), "sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	version := strings.TrimSpace(string(output))
	// Return major version only
	if idx := strings.Index(version, "."); idx > 0 {
		return version[:idx]
	}
	return version
}

// detectWindowsVersion detects Windows version
func detectWindowsVersion() string {
	// Use ver command or fallback
	cmd := exec.CommandContext(context.Background(), "cmd", "/c", "ver")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	// Parse output like "Microsoft Windows [Version 10.0.19041.1234]"
	str := string(output)
	if idx := strings.Index(str, "Version "); idx >= 0 {
		versionStr := str[idx+8:]
		if idx2 := strings.Index(versionStr, "]"); idx2 >= 0 {
			versionStr = versionStr[:idx2]
		}
		// Extract major version
		if idx3 := strings.Index(versionStr, "."); idx3 > 0 {
			return versionStr[:idx3]
		}
	}
	return ""
}

// expandMacros expands $(VAR) references in a value
//
//nolint:unused // Reserved for future use
func (c *Config) expandMacros(value string) (string, error) {
	result := value
	maxDepth := 100
	depth := 0

	for depth < maxDepth {
		// Look for the next macro
		dollarIdx := strings.Index(result, "$(")
		if dollarIdx == -1 {
			break // No more macros
		}

		// Find the matching closing paren (handling nested parens)
		parenDepth := 1
		endIdx := -1
		for i := dollarIdx + 2; i < len(result); i++ {
			if result[i] == '(' {
				parenDepth++
			} else if result[i] == ')' {
				parenDepth--
				if parenDepth == 0 {
					endIdx = i
					break
				}
			}
		}

		if endIdx == -1 {
			return value, fmt.Errorf("unmatched parentheses in macro: %s", result[dollarIdx:])
		}

		// Extract the macro content
		varName := result[dollarIdx+2 : endIdx]

		// If varName contains a macro itself, recursively expand it first
		if strings.Contains(varName, "$(") {
			expanded, err := c.expandMacros(varName)
			if err != nil {
				return value, err
			}
			varName = expanded
		}

		// Handle metaknob parameter special syntax
		// $(0), $(0?), $(0#), $(1), $(1?), $(1+), etc.
		if len(varName) > 0 && varName[0] >= '0' && varName[0] <= '9' {
			replacement := c.expandMetaknobParam(varName)
			result = result[:dollarIdx] + replacement + result[endIdx+1:]
			depth++
			continue
		}

		// Handle default values VAR:default
		parts := strings.SplitN(varName, ":", 2)
		varName = parts[0]
		defaultVal := ""
		if len(parts) > 1 {
			defaultVal = parts[1]
		}

		// $(DOLLAR) is a predefined macro that expands to a literal '$'.
		// HTCondor handles it in expand_macro itself, independent of the
		// defaults table, so it must resolve even in a defaults-free parse.
		if strings.EqualFold(varName, "DOLLAR") {
			result = result[:dollarIdx] + "$" + result[endIdx+1:]
			depth++
			continue
		}

		// Check for circular reference
		if c.evaluating[varName] {
			// Skip this macro to avoid infinite loop
			result = result[:dollarIdx] + "$(" + varName + ")" + result[endIdx+1:]
			break
		}

		c.evaluating[varName] = true

		// Get value. Resolve through the subsystem/local-name scoping that Get()
		// uses, so `$(IsMaster)` under SUBSYSTEM=MASTER expands via MASTER.IsMaster,
		// and any `$(KNOB)` picks up a `SUBSYS.KNOB` override -- matching HTCondor,
		// where macro expansion is subsystem-scoped.
		replacement := defaultVal
		if val, ok := c.values[c.scopedLookupKey(varName)]; ok {
			replacement = val
		}

		delete(c.evaluating, varName)

		// Replace the macro with its value
		result = result[:dollarIdx] + replacement + result[endIdx+1:]
		depth++
	}

	if depth >= maxDepth {
		return value, fmt.Errorf("macro expansion depth exceeded")
	}

	return result, nil
}

// expandMetaknobParam expands metaknob parameter references
// Supports: $(0), $(0?), $(0#), $(N), $(N?), $(N+) where N is 1-9
func (c *Config) expandMetaknobParam(param string) string {
	// Parse the parameter specification
	// Format: N[?|#|+][:default]

	// Check for default value
	parts := strings.SplitN(param, ":", 2)
	paramSpec := parts[0]
	defaultVal := ""
	if len(parts) > 1 {
		defaultVal = parts[1]
	}

	if len(paramSpec) == 0 {
		return defaultVal
	}

	// Extract the digit and any suffix
	digit := paramSpec[0]
	suffix := ""
	if len(paramSpec) > 1 {
		suffix = paramSpec[1:]
	}

	// Get the parameter number
	paramNum := int(digit - '0')
	if paramNum < 0 || paramNum > 9 {
		// Not a valid metaknob parameter
		if val, ok := c.values[param]; ok {
			return val
		}
		return defaultVal
	}

	// Collect all available parameters (1-9)
	// Note: We collect ALL parameters up to 9, including empty ones
	// This is needed for cases like: use FEATURE : Knob(arg1, , arg3)
	var allParams []string
	maxParam := 0
	for i := 1; i <= 9; i++ {
		if val, ok := c.values[fmt.Sprintf("%d", i)]; ok {
			allParams = append(allParams, val)
			maxParam = i
		} else {
			// Still append empty to maintain indexing, but don't update maxParam
			allParams = append(allParams, "")
		}
	}
	// Trim to actual number of parameters passed
	if maxParam > 0 {
		allParams = allParams[:maxParam]
	} else {
		allParams = []string{}
	}

	// Handle special cases for $(0...)
	if paramNum == 0 {
		switch suffix {
		case "?": // $(0?) - returns "1" if any args exist, "0" otherwise
			if len(allParams) > 0 {
				return "1"
			}
			return "0"

		case "#": // $(0#) - returns the number of arguments
			return fmt.Sprintf("%d", len(allParams))

		default: // $(0) or $(0:default) - returns all arguments joined by ", "
			if len(allParams) > 0 {
				return strings.Join(allParams, ", ")
			}
			return defaultVal
		}
	}

	// Handle $(N?), $(N+), $(N) for N = 1-9
	switch suffix {
	case "?": // $(N?) - returns "1" if parameter N exists and is non-empty, "0" otherwise
		if paramNum <= len(allParams) && allParams[paramNum-1] != "" {
			return "1"
		}
		return "0"

	case "+": // $(N+) - returns parameters from N onwards, joined by ", "
		if paramNum <= len(allParams) {
			return strings.Join(allParams[paramNum-1:], ", ")
		}
		return defaultVal

	default: // $(N) or $(N:default) - returns parameter N
		if paramNum <= len(allParams) {
			return allParams[paramNum-1]
		}
		return defaultVal
	}
}

// parseReader parses configuration from an io.Reader
func (c *Config) parseReader(r io.Reader, filename string) error {
	if filename != "" {
		// Track included file to prevent cycles
		if c.includedFiles[filename] {
			return fmt.Errorf("circular include detected: %s", filename)
		}
		c.includedFiles[filename] = true
	}

	scanner := bufio.NewScanner(r)
	var currentLine string
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Handle line continuation
		if strings.HasSuffix(strings.TrimSpace(line), "\\") {
			currentLine += strings.TrimSuffix(strings.TrimRight(line, " \t"), "\\")
			continue
		}

		currentLine += line

		// Process the complete line
		if err := c.parseLine(currentLine); err != nil {
			return fmt.Errorf("line %d: %w", lineNum, err)
		}

		currentLine = ""
	}

	return scanner.Err()
}

// parseLine parses a single configuration line
//
//nolint:unparam // Returns error for interface consistency with other parse functions
func (c *Config) parseLine(line string) error {
	// Trim whitespace
	line = strings.TrimSpace(line)

	// Skip empty lines and comments
	if line == "" || strings.HasPrefix(line, "#") {
		return nil
	}

	// Skip [Section] headers
	if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
		return nil
	}

	// Find the = operator
	eqIdx := strings.Index(line, "=")
	if eqIdx == -1 {
		return nil // Not an assignment, skip
	}

	key := strings.TrimSpace(line[:eqIdx])
	value := strings.TrimSpace(line[eqIdx+1:])

	// Store the value
	c.Set(key, value)

	return nil
}

// LoadFromEnvironment loads configuration from the process environment
func (c *Config) LoadFromEnvironment() error {
	// Look for _CONDOR_ prefixed environment variables
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "_CONDOR_") || strings.HasPrefix(env, "_condor_") {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimPrefix(parts[0], "_CONDOR_")
				key = strings.TrimPrefix(key, "_condor_")
				c.Set(key, parts[1])
			}
		}
	}

	// Locate the root configuration file: CONDOR_CONFIG, or a default location.
	rootPath := os.Getenv("CONDOR_CONFIG")
	if rootPath == "ONLY_ENV" {
		// Explicit request to skip all file loading.
		return nil
	}
	if rootPath == "" {
		for _, path := range []string{"/etc/condor/condor_config", "/usr/local/etc/condor_config"} {
			if _, err := os.Stat(path); err == nil {
				rootPath = path
				break
			}
		}
	}
	if rootPath == "" {
		// No config file found, that's OK.
		return nil
	}

	if err := c.parseConfigFile(rootPath); err != nil {
		return err
	}

	// HTCondor then reads the local configuration chain, with later sources
	// overriding earlier ones: the LOCAL_CONFIG_DIR directories (config.d, files
	// in lexicographic order) followed by the LOCAL_CONFIG_FILE list. Without
	// this, anything defined there -- commonly LOG, LOCAL_DIR, security, and pool
	// knobs on a production install -- is silently missed and the built-in
	// param defaults win instead (e.g. LOG resolves to $(LOCAL_DIR)/log rather
	// than the config.d override).
	if err := c.processLocalConfigDir(); err != nil {
		return err
	}
	return c.processLocalConfigFile()
}

// parseConfigFile opens and parses a single configuration file at path.
func (c *Config) parseConfigFile(path string) (err error) {
	//nolint:gosec // G304: config path comes from CONDOR_CONFIG / known defaults
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close config file: %w", cerr)
		}
	}()
	return c.parseReader(f, path)
}

// processLocalConfigDir processes directories listed in LOCAL_CONFIG_DIR
// Directories are processed left-to-right, files within each directory are
// processed in lexicographical order
func (c *Config) processLocalConfigDir() error {
	dirList, ok := c.Get("LOCAL_CONFIG_DIR")
	if !ok || dirList == "" {
		return nil
	}

	// Split on comma and/or space
	dirs := SplitConfigList(dirList)

	// Files whose basename matches LOCAL_CONFIG_DIR_EXCLUDE_REGEXP are skipped --
	// this is how HTCondor keeps editor backups, package leftovers (.rpmnew,
	// .dpkg-dist), and helper scripts (.py/.sh/.pl) out of config.d parsing. A
	// config.d without this filter would try to parse those as config and fail or
	// mis-set values.
	var excludeRe *regexp.Regexp
	if pat, ok := c.Get("LOCAL_CONFIG_DIR_EXCLUDE_REGEXP"); ok && pat != "" {
		if re, err := regexp.Compile(pat); err == nil {
			excludeRe = re
		}
	}

	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}

		// Check if directory exists
		info, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue // Skip non-existent directories
			}
			return fmt.Errorf("error accessing directory %s: %w", dir, err)
		}

		if !info.IsDir() {
			continue // Skip non-directories
		}

		// Read directory entries
		entries, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("error reading directory %s: %w", dir, err)
		}

		// Sort entries lexicographically (ReadDir already returns sorted)
		for _, entry := range entries {
			if entry.IsDir() {
				continue // Skip subdirectories
			}
			if excludeRe != nil && excludeRe.MatchString(entry.Name()) {
				continue // Excluded by LOCAL_CONFIG_DIR_EXCLUDE_REGEXP
			}

			filePath := filepath.Join(dir, entry.Name())

			// Open and parse the file
			//nolint:gosec // G304: Config directory path comes from validated configuration
			f, err := os.Open(filePath)
			if err != nil {
				return fmt.Errorf("error opening %s: %w", filePath, err)
			}
			err = c.parseAndExecute(f)
			if cerr := f.Close(); cerr != nil && err == nil {
				err = fmt.Errorf("failed to close file: %w", cerr)
			}

			if err != nil {
				return fmt.Errorf("error parsing %s: %w", filePath, err)
			}
		}
	}

	return nil
}

// processLocalConfigFile processes files listed in LOCAL_CONFIG_FILE
// Files are processed left-to-right
func (c *Config) processLocalConfigFile() error {
	fileList, ok := c.Get("LOCAL_CONFIG_FILE")
	if !ok || fileList == "" {
		return nil
	}

	// Split on comma and/or space
	files := SplitConfigList(fileList)

	for _, file := range files {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}

		// Check if this is a command (ends with |)
		if strings.HasSuffix(file, "|") {
			// Execute command and parse output
			cmdLine := strings.TrimSuffix(file, "|")
			cmdLine = strings.TrimSpace(cmdLine)
			if err := c.includeCommand(cmdLine); err != nil {
				return fmt.Errorf("error executing command %q: %w", cmdLine, err)
			}
			continue
		}

		// Regular file - open and parse
		//nolint:gosec // G304: File path comes from validated config directive
		f, err := os.Open(file)
		if err != nil {
			// A missing LOCAL_CONFIG_FILE is tolerated unless
			// REQUIRE_LOCAL_CONFIG_FILE is true (HTCondor's shipped config sets it
			// false and points LOCAL_CONFIG_FILE at a file that need not exist).
			required, _ := c.Get("REQUIRE_LOCAL_CONFIG_FILE")
			if os.IsNotExist(err) && !c.isTruthy(required) {
				continue
			}
			return fmt.Errorf("error opening %s: %w", file, err)
		}
		err = c.parseAndExecute(f)
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close file: %w", cerr)
		}

		if err != nil {
			return fmt.Errorf("error parsing %s: %w", file, err)
		}
	}

	return nil
}

// SplitConfigList splits a configuration list on commas and/or spaces -- the
// delimiters of an HTCondor StringList. Use it for any config value that names a
// list (auth/crypto methods, directories, ...), so "A,B", "A B", and "A, B" are
// all equivalent.
func SplitConfigList(list string) []string {
	// Replace commas with spaces
	list = strings.ReplaceAll(list, ",", " ")

	// Split on whitespace
	parts := strings.Fields(list)

	return parts
}
