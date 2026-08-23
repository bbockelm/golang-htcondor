// Package htcondor provides a Go client library for HTCondor. This file adds helpers for
// locating a peer daemon by its address file.
package htcondor

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bbockelm/golang-htcondor/config"
)

// AddressFilePath returns where subsys writes its address file: the <SUBSYS>_ADDRESS_FILE
// config value if set, otherwise $(LOG)/.<subsys>_address (the HTCondor default). It
// returns "" when neither is resolvable (no override and LOG unset). subsys is the
// upper-case subsystem name (e.g. "HTCONDORDB", "COLLECTOR").
//
// A DaemonCore daemon writes its current contact address to this file as a single-line
// sinful string. That address is NOT stable: under shared port it carries a per-run socket
// token that changes every time condor_master restarts the daemon, so a client that caches
// the address once goes stale on restart. Pair this with FileAddressResolver so a
// reconnecting client re-reads the file and follows a restarted daemon automatically.
func AddressFilePath(cfg *config.Config, subsys string) string {
	if v, ok := cfg.Get(subsys + "_ADDRESS_FILE"); ok {
		if p := strings.TrimSpace(v); p != "" {
			return p
		}
	}
	if v, ok := cfg.Get("LOG"); ok {
		if logDir := strings.TrimSpace(v); logDir != "" {
			return filepath.Join(logDir, "."+strings.ToLower(subsys)+"_address")
		}
	}
	return ""
}

// ReadAddressFile returns the first non-empty line of an HTCondor address file: a sinful
// string, possibly angle-bracket wrapped (cedar's addresses.ParseSinful accepts either
// form, and ConnectAndAuthenticate takes it as-is).
func ReadAddressFile(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is an operator-configured address-file location from HTCondor config, not user input

	if err != nil {
		return "", fmt.Errorf("reading address file %s: %w", path, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s, nil
		}
	}
	return "", fmt.Errorf("address file %s is empty", path)
}

// FileAddressResolver returns a function that re-reads path (via ReadAddressFile) on every
// call. Give it to a client that reconnects -- e.g. a connection pool that re-dials on
// failure -- so each reconnect picks up the daemon's current address instead of a cached,
// possibly-restarted-away one. A transient read failure surfaces to the caller (which
// should back off and retry) rather than yielding a stale address.
func FileAddressResolver(path string) func() (string, error) {
	return func() (string, error) { return ReadAddressFile(path) }
}

// LocalDaemonAddress resolves subsys's address for a peer using the standard knobs, and
// returns a resolver plus a one-line description of the source (for logging). On each call
// the resolver prefers the daemon's address file (AddressFilePath) when that file is
// present and readable -- so a co-located daemon is followed across restarts -- and
// otherwise falls back to the static <SUBSYS>_HOST knob (e.g. a daemon on another host with
// no local address file). It errors at construction only when neither a file path nor a
// host is configured; a per-call file-read error still falls back to <SUBSYS>_HOST if one
// is set, else surfaces so the caller can retry.
//
// A caller with its own knob names (e.g. a collector using COLLECTOR_DB_HOST /
// COLLECTOR_DB_ADDRESS_FILE rather than the <SUBSYS>_* convention) should instead compose
// AddressFilePath / FileAddressResolver directly with its own precedence.
func LocalDaemonAddress(cfg *config.Config, subsys string) (func() (string, error), string, error) {
	path := AddressFilePath(cfg, subsys)
	host := ""
	if v, ok := cfg.Get(subsys + "_HOST"); ok {
		host = strings.TrimSpace(v)
	}
	if path == "" && host == "" {
		return nil, "", fmt.Errorf("cannot locate %s: set %s_ADDRESS_FILE or %s_HOST (or LOG so $(LOG)/.%s_address resolves)",
			subsys, subsys, subsys, strings.ToLower(subsys))
	}
	source := describeSource(path, host)
	resolve := func() (string, error) {
		if path != "" {
			if addr, err := ReadAddressFile(path); err == nil {
				return addr, nil
			} else if host == "" {
				return "", err // no fallback; let the caller retry
			}
		}
		return host, nil
	}
	return resolve, source, nil
}

func describeSource(path, host string) string {
	switch {
	case path != "" && host != "":
		return "address file " + path + " (fallback " + host + ")"
	case path != "":
		return "address file " + path
	default:
		return host
	}
}

// ScheddTarget is what a SCHEDD_HOST setting points at. HTCondor
// documents the knob as "the host name of the machine where the
// condor_schedd is running for your pool", with the name included as
// name@hostname when that host sets SCHEDD_NAME or MASTER_NAME. It is
// undefined in most pools, so a defined value is a deliberate
// instruction to talk to that schedd rather than whichever one happens
// to be local or first in the collector.
type ScheddTarget struct {
	// Name is the schedd's name when SCHEDD_HOST was written as
	// name@hostname, otherwise empty.
	Name string
	// Host is the machine the schedd runs on. May carry a ":port"
	// suffix, in which case Address reports it as a directly dialable
	// address and no collector lookup is needed.
	Host string
}

// ParseScheddHost splits a SCHEDD_HOST value into its parts. An empty or
// whitespace-only value yields the zero ScheddTarget, whose IsSet
// reports false.
func ParseScheddHost(value string) ScheddTarget {
	value = strings.TrimSpace(value)
	if value == "" {
		return ScheddTarget{}
	}
	// Rightmost '@' wins: a schedd name may itself contain one
	// ("submit@cluster@host" is not valid HTCondor, but splitting from
	// the right is the reading that keeps the host intact).
	if i := strings.LastIndex(value, "@"); i >= 0 {
		return ScheddTarget{Name: strings.TrimSpace(value[:i]), Host: strings.TrimSpace(value[i+1:])}
	}
	return ScheddTarget{Host: value}
}

// IsSet reports whether the target names anything.
func (t ScheddTarget) IsSet() bool { return t.Name != "" || t.Host != "" }

// Address returns a directly dialable address when SCHEDD_HOST included
// a port, and "" when the target still has to be looked up in the
// collector.
func (t ScheddTarget) Address() string {
	if t.Host == "" {
		return ""
	}
	// A bracketed IPv6 literal with a port ("[::1]:9618") or a
	// host:port pair. A bare IPv6 literal has more than one colon and
	// no brackets, which is not a port.
	if strings.HasPrefix(t.Host, "[") {
		if i := strings.LastIndex(t.Host, "]:"); i >= 0 {
			return t.Host
		}
		return ""
	}
	if strings.Count(t.Host, ":") == 1 {
		return t.Host
	}
	return ""
}

// CollectorConstraint returns the ClassAd constraint that selects this
// target's ScheddAd in the collector, or "" when the target names
// nothing to constrain on.
func (t ScheddTarget) CollectorConstraint() string {
	switch {
	case t.Name != "" && t.Host != "":
		// Both known: the name identifies the schedd, and HTCondor
		// spells a named schedd's Name as "name@hostname".
		return fmt.Sprintf("Name == %q || Name == %q", t.Name+"@"+t.Host, t.Name)
	case t.Name != "":
		return fmt.Sprintf("Name == %q", t.Name)
	case t.Host != "":
		// Match the machine, and also the common case of an unnamed
		// schedd whose Name is just the hostname.
		return fmt.Sprintf("Machine == %q || Name == %q", t.Host, t.Host)
	default:
		return ""
	}
}
