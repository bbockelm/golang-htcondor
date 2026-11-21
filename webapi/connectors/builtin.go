package connectors

import (
	"sort"

	"golang.org/x/oauth2"
)

// The builtin catalogue: definitions that ship with this server.
//
// A builtin carries the things an operator should not have to know --
// endpoints, the narrowest scope that works, whether a transfer plugin
// exists for it -- and asks them only for what is theirs: the client
// registration and who may use it.
//
// It is CLOSED. Configuration cannot add to it, which is what lets a
// shipped definition be corrected in a release: the day a site: id could
// be based on one of these, every field here would become a
// compatibility promise. See design_notes/CONNECTORS.md.

// Kind says who holds the OAuth2 client registration, which is what
// actually distinguishes the three bootstrap mechanisms.
type Kind string

const (
	// KindCredd means the OAuth credmon is the client. We obtain the URL it
	// mints and redirect; we store nothing.
	KindCredd Kind = "credd"
	// KindVault means HashiCorp Vault is the client. We initiate its OIDC
	// flow, poll, and hand the resulting Vault token to the credd.
	KindVault Kind = "vault"
	// KindOAuth2 means we are the client. Only this kind touches the
	// database, and only this kind can produce a credential that
	// outlives a browser session.
	KindOAuth2 Kind = "oauth2"
)

// Valid reports whether k is a kind this server implements.
func (k Kind) Valid() bool {
	switch k {
	case KindCredd, KindVault, KindOAuth2:
		return true
	}
	return false
}

// Transfer is how a connector's data reaches a job.
type Transfer string

const (
	// TransferSpool means this server fetches the bytes and spools them as
	// job input. No third-party token reaches an execute node. The
	// default, because it needs nothing deployed anywhere.
	TransferSpool Transfer = "spool"
	// TransferDirect means the credential goes to the credd and the transfer
	// plugin on the execute node fetches. Avoids moving bytes twice.
	TransferDirect Transfer = "direct"
)

// Valid reports whether t is a transfer mode this server implements.
func (t Transfer) Valid() bool {
	return t == TransferSpool || t == TransferDirect
}

// BuiltinDef is a shipped provider definition.
type BuiltinDef struct {
	// Kind is always KindOAuth2 today. The field exists because the
	// catalogue is the natural home for a shipped credd: or vault:
	// definition too, and leaving it implicit would mean finding every
	// place that assumed.
	Kind Kind
	// AuthorizationURL and TokenURL are transcribed from HTCondor's own
	// parameter defaults (config/param_defaults.go, which carries
	// <PROVIDER>_AUTHORIZATION_URL and _TOKEN_URL for exactly these
	// providers). Taking them from there rather than from a provider's
	// documentation means the two cannot disagree about a provider
	// HTCondor already supports.
	AuthorizationURL string
	TokenURL         string
	// DefaultScopes is the narrowest scope set that does the job. For
	// Drive that is drive.file, which is per-file and granted by the
	// user picking a file. Narrow is not only a compliance choice: in
	// direct mode this token sits on an execute node, so scope width is
	// blast radius.
	DefaultScopes []string
	// TransferMethod is the HTCondor file transfer plugin method that
	// can use this credential, empty when none ships. A credential with
	// no plugin is still useful -- a job can read $_CONDOR_CREDS itself
	// -- but it cannot be used in direct transfer mode.
	TransferMethod string
	// Summary is one line for the admin page's catalogue.
	Summary string

	// AuthStyle is how the client credentials go on a token request.
	//
	// Worth setting, because the zero value makes x/oauth2 PROBE: it
	// sends the request with the secret in the Authorization header,
	// and on ANY error -- including a 503 -- silently retries once with
	// the secret in the body (internal/token.go:216-246). Two things
	// follow. The secret goes out in two forms on the first request,
	// and a single transient failure is invisible, but only until the
	// style is cached, after which it is not. Failures that depend on
	// how many requests have gone before are the hardest kind to
	// reason about.
	//
	// Set only where the provider's documentation has actually been
	// read. The zero value keeps the probe, which is the right
	// behaviour for a provider nobody has checked.
	AuthStyle oauth2.AuthStyle
}

// builtins is the catalogue, keyed by name within the builtin namespace.
var builtins = map[string]BuiltinDef{
	"gdrive": { //nolint:gosec // G101: published endpoint, not a credential
		Kind:             KindOAuth2,
		AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:         "https://oauth2.googleapis.com/token",
		DefaultScopes:    []string{"https://www.googleapis.com/auth/drive.file"},
		// Google's web-server page lists client_secret among the token
		// request's PARAMETERS and its sample body sends client_id
		// there, so the credentials go in the body and no probe is
		// needed. Read 2026-11-21; see connectors/mockgoogle.
		AuthStyle:      oauth2.AuthStyleInParams,
		TransferMethod: "gdrive",
		Summary:        "Google Drive, limited to files the user picks",
	},
	"box": { //nolint:gosec // G101: published endpoint, not a credential
		Kind:             KindOAuth2,
		AuthorizationURL: "https://account.box.com/api/oauth2/authorize",
		TokenURL:         "https://api.box.com/oauth2/token",
		TransferMethod:   "box",
		Summary:          "Box",
	},
	"onedrive": { //nolint:gosec // G101: published endpoint, not a credential
		Kind:             KindOAuth2,
		AuthorizationURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
		TokenURL:         "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		TransferMethod:   "onedrive",
		Summary:          "Microsoft OneDrive",
	},
	"dropbox": { //nolint:gosec // G101: published endpoint, not a credential
		Kind:             KindOAuth2,
		AuthorizationURL: "https://www.dropbox.com/oauth2/authorize",
		TokenURL:         "https://api.dropboxapi.com/oauth2/token",
		// HTCondor defines Dropbox's endpoints but ships no transfer
		// plugin for it, so a Dropbox credential cannot be used in
		// direct mode. Carried anyway: the endpoints are free and the
		// spool path does not need a plugin.
		TransferMethod: "",
		Summary:        "Dropbox (no transfer plugin; spool only)",
	},
}

// Lookup returns the shipped definition for a builtin id.
func Lookup(id ID) (BuiltinDef, bool) {
	if id.Namespace != Builtin {
		return BuiltinDef{}, false
	}
	def, ok := builtins[id.Name]
	return def, ok
}

// BuiltinIDs lists the catalogue, in a fixed order, for the admin page's
// "enable a built-in" picker.
func BuiltinIDs() []ID {
	out := make([]ID, 0, len(builtins))
	for name := range builtins {
		out = append(out, ID{Namespace: Builtin, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
