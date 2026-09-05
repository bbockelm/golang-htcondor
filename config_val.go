package htcondor

import (
	"context"
	"fmt"
	"strings"

	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
)

// notDefinedReply is what daemon core sends when the requested parameter has
// no value. It is a literal string on the wire, not an error code, so it has
// to be recognized by content — see handle_config_val in daemon_core_main.cpp.
const notDefinedReply = "Not defined"

// ConfigVal asks a daemon for the value of one configuration parameter, the
// way `condor_config_val -<daemon>` does.
//
// This reads the DAEMON's view of its configuration, which is the point: the
// answer can differ from what this process would compute locally, because the
// daemon may run on another host, have been started with a different
// CONDOR_CONFIG, or simply not have been reconfigured since the file changed.
// For anything used to make an authorization decision, the daemon's own
// answer is the only one that means anything.
//
// The command is registered at READ authorization on the daemon side, so this
// needs no special privilege.
//
// A parameter with no value returns ("", false, nil) — an unset knob is a
// normal answer, not a failure.
func (s *Schedd) ConfigVal(ctx context.Context, name string) (value string, ok bool, err error) {
	if strings.TrimSpace(name) == "" {
		return "", false, fmt.Errorf("parameter name is required")
	}
	// A leading '?' selects daemon core's meta-commands (?names, ?stats)
	// rather than a parameter lookup. Those have a different reply shape,
	// so refuse rather than mis-parse the response.
	if strings.HasPrefix(name, "?") {
		return "", false, fmt.Errorf("meta-queries (%q) are not supported by ConfigVal", name)
	}

	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, int(commands.DC_CONFIG_VAL), "CLIENT", s.address)
	if err != nil {
		return "", false, fmt.Errorf("failed to create security config: %w", err)
	}

	htcondorClient, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
	if err != nil {
		return "", false, wrapScheddConnectError(s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	stream := htcondorClient.GetStream()

	req := message.NewMessageForStream(stream)
	if err := req.PutString(ctx, name); err != nil {
		return "", false, fmt.Errorf("failed to send parameter name: %w", err)
	}
	if err := req.FinishMessage(ctx); err != nil {
		return "", false, fmt.Errorf("failed to send config value request: %w", err)
	}

	resp := message.NewMessageFromStream(stream)
	raw, err := resp.GetString(ctx)
	if err != nil {
		return "", false, fmt.Errorf("failed to read config value for %s: %w", name, err)
	}
	if raw == notDefinedReply {
		return "", false, nil
	}
	return raw, true, nil
}

// QueueSuperUsers returns the schedd's effective QUEUE_SUPER_USERS set, in
// the identity form the schedd compares against: each configured name is
// returned both bare and qualified with the schedd's UID_DOMAIN.
//
// The qualification mirrors what the schedd does when it builds its own set
// (see the "Backward compatibility hack" in qmgmt.cpp): QUEUE_SUPER_USERS
// historically named OS users, while authenticated identities are
// "user@domain", so a configured "condor" also makes "condor@$(UID_DOMAIN)"
// a superuser. A caller comparing an authenticated identity against this set
// would otherwise never match.
//
// This does NOT reproduce every alternate identity the schedd accepts —
// condor@child, condor@parent and condor@password are session-internal
// identities that no web caller will ever present, and PERSONAL_CONDOR_IS_
// SUPER_USER adds the process owner in a way that is only observable inside
// the daemon. The set returned here is therefore a SUBSET of what the schedd
// will accept: a caller may conclude "not a superuser" for an identity the
// schedd would in fact allow. That direction is the safe one — it costs a
// fallback to a less specific identity, never an unearned privilege.
func (s *Schedd) QueueSuperUsers(ctx context.Context) ([]string, error) {
	raw, ok, err := s.ConfigVal(ctx, "QUEUE_SUPER_USERS")
	if err != nil {
		return nil, err
	}
	if !ok {
		// Unset means the schedd is using its compiled-in default. Do not
		// guess it here: returning the wrong set would silently change who
		// this server thinks may act as whom.
		return nil, nil
	}

	uidDomain, _, err := s.ConfigVal(ctx, "UID_DOMAIN")
	if err != nil {
		// The names are still usable unqualified; a caller comparing a
		// fully-qualified identity just won't match, which is the safe
		// direction.
		uidDomain = ""
	}

	return qualifySuperUsers(raw, uidDomain), nil
}

// qualifySuperUsers expands a QUEUE_SUPER_USERS value into the identity forms
// the schedd compares against, preserving order and dropping duplicates.
func qualifySuperUsers(raw, uidDomain string) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			return
		}
		seen[v] = true
		out = append(out, v)
	}
	for _, name := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		add(name)
		if uidDomain != "" && !strings.Contains(name, "@") {
			add(name + "@" + uidDomain)
		}
	}
	return out
}
