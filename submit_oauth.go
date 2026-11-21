package htcondor

import (
	"regexp"
	"sort"
	"strings"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/htcondor/golang-htcondor/config"
)

// oauthSettingKey matches the submit commands that configure one OAuth
// credential: `<service>_oauth_permissions`, `<service>_oauth_resource` and
// `<service>_oauth_options`, each optionally followed by `_<handle>`.
//
// It is unanchored on both ends, exactly as the PCRE2 pattern in
// SubmitHash::NeedsOAuthServices is: the service name is whatever precedes
// the first match, and the handle whatever follows it. So the match decides
// where the name ends rather than the name deciding where to look, and a
// service whose own name contains `_oauth_resource` would be cut at the
// first one. That is what condor_submit does with it.
var oauthSettingKey = regexp.MustCompile(`(?i)_oauth_(permissions|resource|options)`)

// setOAuthServices writes OAuthServicesNeeded, the list of credentials the
// job cannot run without, from the `use_oauth_services` submit command
// (SubmitHash::SetOAuth).
//
// The schedd's credd hands the shadow the credentials named here and the
// starter writes them into $_CONDOR_CREDS; a job that asks for none carries
// no attribute at all. Without it the job runs with an empty $_CONDOR_CREDS,
// or -- on an access point that holds every job whose credentials are absent
// -- never runs.
func (sf *SubmitFile) setOAuthServices(ad *classad.ClassAd) {
	services := sf.OAuthServicesNeeded()
	if len(services) == 0 {
		return
	}
	_ = ad.Set("OAuthServicesNeeded", strings.Join(services, ","))
}

// OAuthServicesNeeded returns the OAuth credentials the submit file asks for,
// in the order they appear in the job's OAuthServicesNeeded attribute: the
// bare service name, or `<service>*<handle>` where the submit file configured
// the service under a handle.
//
// It is SubmitHash::NeedsOAuthServices with add_local false -- the submit
// file's own request, without the services an access point's configuration
// adds to every job (LOCAL_CREDMON_PROVIDER_NAMES and friends). Those belong
// to the credd and the schedd, which add them to a job that does not name
// them; condor_submit consults them only to decide what to ask the credd for
// before it submits.
//
// A handle makes a credential of its own, and the bare name survives only if
// something configured the service without one. So
//
//	use_oauth_services = scitokens
//	scitokens_oauth_permissions_restricted = read:/data
//
// asks for `scitokens*restricted` and not for `scitokens`, while adding a
// second, handleless `scitokens_oauth_permissions` asks for both.
func (sf *SubmitFile) OAuthServicesNeeded() []string {
	if sf == nil {
		return nil
	}
	value, ok := sf.submitCommandAlt("use_oauth_services", "UseOAuthServices")
	if !ok {
		return nil
	}

	// The bare service names as the submitter wrote them. These are not
	// necessarily the credential names: a handle below mutates one.
	enabled := make(map[string]string)
	for _, name := range splitSubmitTokens(value, ", \t\r\n") {
		key := strings.ToLower(name)
		if _, seen := enabled[key]; !seen {
			enabled[key] = name
		}
	}
	if len(enabled) == 0 {
		return nil
	}

	// Service names are compared and deduplicated without regard to case,
	// as the classad::References that holds them in C++ does, and the
	// first spelling to arrive is the one that reaches the attribute.
	names := make(map[string]string)
	addName := func(name string) {
		key := strings.ToLower(name)
		if _, seen := names[key]; !seen {
			names[key] = name
		}
	}

	// Every submit command that configures one of the enabled services.
	// Walking what the submit FILE assigned, rather than every macro in
	// scope, keeps a configuration knob that happens to be spelled like
	// one of these from adding a credential to the job; see submitCommand.
	withHandles := make(map[string]bool)
	for _, key := range sf.assignedOAuthSettings() {
		m := oauthSettingKey.FindStringIndex(key)
		if m == nil {
			continue
		}
		service := key[:m[0]]
		if _, want := enabled[strings.ToLower(service)]; !want {
			continue
		}
		if len(key) > m[1] {
			// `<service>_oauth_permissions_<handle>`: the handle is
			// everything past the separator, and it becomes part of
			// the credential's name.
			withHandles[strings.ToLower(service)] = true
			service += "*" + key[m[1]+1:]
		}
		addName(service)
	}

	// Then the services nothing configured under a handle, which are asked
	// for under their bare name.
	for key, name := range enabled {
		if withHandles[key] {
			continue
		}
		addName(name)
	}

	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

// assignedOAuthSettings returns the names the submit file assigned that could
// configure an OAuth service, in a fixed order.
//
// The order only decides which spelling of a name that two commands wrote
// differently survives, which is why C++ can leave it to its hash table.
// Sorting here makes one submit file always produce one job ad.
//
// A `+Attr` or `MY.Attr` is a job attribute rather than a submit command and
// is passed over, as NeedsOAuthServices passes it over. The prefix usually
// makes the service name fail to match on its own -- `+scitokens_oauth_...`
// reads as a service called `MY.scitokens` and no job asks for that one --
// so the only submit file this changes the answer for is one whose service
// is itself named `MY.something`, which then keeps its bare name rather than
// taking the handle.
func (sf *SubmitFile) assignedOAuthSettings() []string {
	var keys []string
	attrPrefix := strings.ToUpper(config.CustomAttrPrefix)
	for upper, name := range sf.assigned {
		if strings.HasPrefix(upper, attrPrefix) {
			continue
		}
		// Nothing without this can match oauthSettingKey. The regexp
		// decides; this only keeps it off every other submit command.
		if !strings.Contains(upper, "_OAUTH_") {
			continue
		}
		keys = append(keys, name)
	}
	sort.Strings(keys)
	return keys
}
