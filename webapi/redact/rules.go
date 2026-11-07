package redact

import (
	"regexp"
	"strings"
)

// The rule set: three groups, run in this order.
//
//  1. formatRules -- recognised by their own structure. A JWT, a PEM
//     block, a base64 Kerberos ticket. These carry most of the weight,
//     because the credentials this access point actually handles
//     (SciTokens, WLCG tokens, HTCondor IDTOKENs, X.509 proxies,
//     Kerberos tickets) are identified by shape and by nothing else --
//     their issuers stamp no prefix on them.
//
//  2. issuerRules -- recognised by a published prefix. ghp_, xoxb-,
//     AKIA. These schemes exist so that scanners can find a leaked
//     token, and a job that pulls a model from Hugging Face or pushes
//     an image to a registry has one in its environment.
//
//  3. contextRules -- recognised by where they sit. The name of the
//     field holding it, the header it follows, its place in a URL. This
//     is what catches an opaque token no prefix covers, which is most
//     of them.
//
// The order is what lets a rule keep the useful half of a credential:
// each group is more precise than the next, and a span already carrying
// a marker is left alone (see replaceGroup), so the first rule to
// recognise something decides how much of it goes.
//
// There is deliberately no fourth group. No entropy test, no "32 hex
// characters": job output is full of checksums, UUIDs, accession
// numbers and base64 payloads, and a filter that ate those is one an
// operator turns off, which protects nothing at all.

// Default returns the rules in force unless a site turns some off.
//
// Built fresh on each call: a Redactor is immutable, but the caller owns
// the slice and may filter it.
func Default() []Rule {
	rules := make([]Rule, 0, 32)
	rules = append(rules, formatRules()...)
	rules = append(rules, issuerRules()...)
	rules = append(rules, contextRules()...)
	return rules
}

// --- recognised by structure ----------------------------------------------

func formatRules() []Rule {
	return []Rule{
		// JOSE compact serialisation with more than three segments: a
		// JWE, whose payload is ciphertext. Nothing in it is readable, so
		// unlike a signed token there is no part worth keeping.
		//
		// Runs BEFORE the JWT rule. Both start at `eyJ`, and the JWT rule
		// matching the first three segments of a five-segment token would
		// leave the other two -- including the ciphertext and the
		// authentication tag -- sitting in the output.
		{
			ID:      "jwe",
			What:    "encrypted JOSE token",
			Needles: []string{"eyJ"},
			Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*){3,}`),
			Skip:    skipIfTokenContinues,
		},

		// A signed JWT: SciToken, WLCG token, HTCondor IDTOKEN, OIDC id
		// token, and most bearer tokens issued in the last decade.
		//
		// Only the signature is replaced. The header and claims are not
		// secret and are the answer to the question the output is usually
		// being read for -- which issuer, which subject, which scopes,
		// expired when. A caller told only "[REDACTED]" has to go and ask
		// a human what the token was for; a caller left with the claims
		// can diagnose the failure itself. Removing the signature is
		// enough: a token cannot be replayed without it.
		//
		// The signature's minimum length keeps an `alg: none` token --
		// which has an empty signature and therefore no secret -- out of
		// the tally, and keeps the rule off three-part identifiers that
		// merely start with the same letters.
		{
			ID:      "jwt-signature",
			What:    "JWT signature",
			Needles: []string{"eyJ"},
			Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.([A-Za-z0-9_-]{16,})`),
			Groups:  []int{1},
			Skip:    skipIfTokenContinues,
		},

		// A PEM private key: an X.509 proxy's key, an SSH key, a host
		// key, a service account key.
		//
		// Certificates are deliberately untouched. In a proxy file the
		// certificate chain is the public, diagnosable half -- subject,
		// issuer, validity, VOMS extensions -- and it is what someone
		// reading a failed job's output needs. The key below it is the
		// secret, and it is the only part that goes.
		//
		// Not a regular expression: a block whose END line is missing --
		// output truncated mid-key, which is when the key is still
		// entirely present -- has no closing delimiter to match on, and
		// RE2's lack of negative lookahead makes "to the END line or the
		// end of the text, whichever comes first" not expressible.
		{
			ID:      "pem-private-key",
			What:    "PEM private key",
			Needles: []string{pemBegin},
			Fn:      redactPEMPrivateKeys,
		},

		// A base64-wrapped Kerberos credential cache or keytab.
		//
		// These are binary, so they reach a caller already base64-encoded
		// -- `get_job_output` encodes any file that is not valid UTF-8,
		// and a job that ships its own ticket does it by hand. The
		// prefixes are what the file's first bytes encode to: 0x0504 is a
		// version 4 credential cache, 0x0501 and 0x0502 are keytabs.
		//
		// The lowest-specificity rule here, since those bytes are not
		// unique to Kerberos. The length floor is what holds the false
		// positive rate down, and this is a first candidate to turn off
		// at a site that sees one.
		{
			ID:      "kerberos-credential",
			What:    "Kerberos ticket or keytab",
			Needles: []string{"BQQA", "BQIA", "BQEA"},
			Pattern: regexp.MustCompile(`\b(?:BQQA|BQIA|BQEA)[A-Za-z0-9+/]{60,}={0,2}`),
		},
	}
}

// credentialFieldNames matches the tail of a field name whose value is a
// credential: the head word only, because the rule is anchored at the
// needle and the needle is the head word.
//
// A head word rather than an enumeration of full names, which is what
// makes `refresh_token`, `sas_token`, `HF_TOKEN`, `my-api-key` and
// `aws_secret_access_key` all fall out of one short alternation instead
// of forty branches. The qualifier in front of it is not matched at all
// -- it is not part of the secret and nothing is decided by it.
//
// Bare `key` is not a head word: too much job output assigns to
// something called `key` for that to be anything but noise. It appears
// only in the compound forms.
const credentialFieldNames = `` +
	`(?:token|secret|password|passwd|passphrase|credential|` +
	`api[-_]?key|private[-_]?key|secret[-_]?key|access[-_]?key|account[-_]?key|signing[-_]?key|` +
	`connection[-_]?string)`

// credentialFieldNeedles prefilter the field rule, and because that rule
// is anchored they also decide WHERE it is tried. Each one must
// therefore be a literal the pattern can begin with -- the head word
// itself, not some fragment of a longer name.
//
// Getting that wrong is invisible except as a rule that quietly stops
// finding things: `api-key:` went unredacted while `apikey:` did not,
// because the needle list had the run-together spelling and the pattern
// had both. TestAnchoredNeedlesAlignWithTheirPattern now checks the
// correspondence rather than leaving it to whichever spellings a test
// happened to try.
//
// Three casings each, since strings.Contains is case-sensitive and the
// pattern is not: a field name arrives lowercase from JSON, capitalised
// from a header, and upper from an environment variable.
var credentialFieldNeedles = casings(
	"token", "secret", "password", "passwd", "passphrase", "credential",
	"api", "private", "access", "account", "signing", "connection",
)

// casings returns each word lowercase, Capitalised and UPPERCASE.
func casings(words ...string) []string {
	out := make([]string, 0, len(words)*3)
	for _, w := range words {
		out = append(out, w, strings.ToUpper(w[:1])+w[1:], strings.ToUpper(w))
	}
	return out
}

// signedURLParams are query parameters whose value authorises a request.
//
// Azure's single-letter SAS parameters (sv, se, sp, sr) are deliberately
// absent: they carry the grant's validity and permissions, not the
// credential, and `sig` -- which is the credential -- is here.
const signedURLParams = `x-amz-signature|x-amz-credential|x-amz-security-token|x-goog-signature|` +
	`awsaccesskeyid|signature|sig|authz|access[-_]?token|id[-_]?token|api[-_]?key|apikey|token`

// signedURLNeedles prefilter the signed-URL rule.
//
// Spelled out per parameter rather than as "?" and "&", which appear in
// almost any text and would leave this rule running its pattern over
// every result -- the prescan would stop being a prescan. Query
// parameter names do not vary in the wild the way field names in a
// config file do, so the handful of spellings below is the whole set.
var signedURLNeedles = []string{
	"X-Amz-", "x-amz-", "X-Goog-", "x-goog-", "AWSAccessKeyId=",
	"authz=", "Authz=", "signature=", "Signature=", "sig=", "Sig=",
	"token=", "Token=", "api_key=", "apikey=", "apiKey=", "API_KEY=",
}

// skipIfTokenContinues rejects a match that is part of something longer.
//
// RE2 has no lookaround, so "this `eyJ` starts a token rather than
// sitting inside one" is checked on the bytes either side. Without the
// check, a longer opaque credential that happens to contain `eyJ` would
// have its middle replaced and its ends left, producing output that
// looks like a token and is not one.
func skipIfTokenContinues(src string, loc []int) bool {
	if loc[0] > 0 && isTokenByte(src[loc[0]-1]) {
		return true
	}
	// A trailing `.` means more segments follow than the pattern
	// accounted for. The pattern's own character class has already eaten
	// every trailing token byte, so this is the only continuation left.
	return loc[1] < len(src) && src[loc[1]] == '.'
}

func isTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9':
		return true
	case b == '_', b == '-', b == '.':
		return true
	}
	return false
}

// placeholders are values that say a credential is absent, which is the
// opposite of the thing being redacted.
var placeholders = []string{
	"null", "none", "nil", "false", "true", "undefined", "unset", "empty",
	"changeme", "redacted", "hidden", "example", "placeholder", "your_token_here",
}

// skipPlaceholderValue keeps the field rule off a value that is not a
// credential: a masked one, a stand-in, or a run of the same character.
//
// The point is the note. A result that says something was redacted sends
// whoever reads it looking for the leak; saying so about `password:
// changeme` in a template wastes that attention and teaches the reader
// to ignore the note.
func skipPlaceholderValue(src string, loc []int) bool {
	start, end := secretSpan([]int{1, 2, 3}, loc)
	if start < 0 {
		return true
	}
	v := strings.TrimSpace(src[start:end])
	if v == "" {
		return true
	}
	lower := strings.ToLower(v)
	for _, p := range placeholders {
		if lower == p {
			return true
		}
	}
	// `****`, `xxxxxxxx`, `........`: already masked by whatever wrote it.
	if allSameByte(v) {
		return true
	}
	return false
}

func allSameByte(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// --- PEM ------------------------------------------------------------------

const pemBegin = "-----BEGIN "

const pemDelim = "-----"

// redactPEMPrivateKeys replaces the body of every PEM private-key block,
// keeping the BEGIN and END lines so the reader can still see what was
// there. Certificates, CSRs and public keys pass through untouched.
func redactPEMPrivateKeys(src string, mark func(string) string) string {
	var b strings.Builder
	b.Grow(len(src))
	pos := 0
	for {
		rel := strings.Index(src[pos:], pemBegin)
		if rel < 0 {
			break
		}
		begin := pos + rel
		labelStart := begin + len(pemBegin)
		labelLen := strings.Index(src[labelStart:], pemDelim)
		// A stray "-----BEGIN " in prose, or output that stops inside the
		// header. Either way there is no block here to redact.
		if labelLen < 0 || labelLen > maxPEMLabel {
			break
		}
		headerEnd := labelStart + labelLen + len(pemDelim)
		if !strings.HasSuffix(src[labelStart:labelStart+labelLen], "PRIVATE KEY") {
			b.WriteString(src[pos:headerEnd])
			pos = headerEnd
			continue
		}

		// The body ends at the END line, or at the end of the text when
		// the output was cut off mid-key -- the case where the key is
		// still entirely present and still has to go.
		bodyEnd := len(src)
		if rel := strings.Index(src[headerEnd:], "-----END "); rel >= 0 {
			bodyEnd = headerEnd + rel
		}
		// Keep the newline that ends the header line, so the replacement
		// reads as a PEM block with its body removed rather than as one
		// run-together line.
		bodyStart := headerEnd
		for bodyStart < bodyEnd && (src[bodyStart] == '\r' || src[bodyStart] == '\n') {
			bodyStart++
		}
		body := src[bodyStart:bodyEnd]
		b.WriteString(src[pos:bodyStart])
		if strings.TrimSpace(body) == "" || strings.HasPrefix(strings.TrimSpace(body), markerPrefix) {
			b.WriteString(body)
		} else {
			b.WriteString(mark(body))
			if bodyEnd < len(src) {
				b.WriteString("\n")
			}
		}
		pos = bodyEnd
	}
	b.WriteString(src[pos:])
	return b.String()
}

// maxPEMLabel bounds what is accepted between "-----BEGIN " and the
// closing dashes. The longest real one is "ENCRYPTED PRIVATE KEY"; the
// bound is what stops a "-----BEGIN " written in prose from swallowing
// the next few kilobytes looking for a delimiter.
const maxPEMLabel = 64

// --- recognised by issuer prefix -------------------------------------------

// issuerRules are the published prefix schemes. Each is a literal prefix
// and a length, which is the whole reason the schemes exist: the issuers
// adopted them so that a scanner could find a leaked token without
// guessing.
//
// The list is not exhaustive and is not trying to be. It covers what a
// job on this access point plausibly holds -- a registry credential for
// a container build, a model-hub token, a cloud key for staging input --
// plus the handful whose leaks are most costly. A site that needs
// another adds it here; a site that finds one noisy turns it off by id.
func issuerRules() []Rule {
	return []Rule{
		prefixRule("github-token", "GitHub token", []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
			`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`),
		prefixRule("github-fine-grained-pat", "GitHub fine-grained token", []string{"github_pat_"},
			`\bgithub_pat_[A-Za-z0-9_]{36,255}\b`),
		prefixRule("gitlab-token", "GitLab token", []string{"glpat-", "glrt-", "gldt-", "glsoat-", "glagent-"},
			`\bgl(?:pat|rt|dt|soat|agent|ptt|cbt|ft)-[A-Za-z0-9_-]{20,}\b`),
		prefixRule("slack-token", "Slack token", []string{"xox"},
			`\bxox[abeoprs]-[A-Za-z0-9-]{10,}\b`),
		prefixRule("slack-app-token", "Slack app token", []string{"xapp-"},
			`\bxapp-[0-9]-[A-Za-z0-9-]{10,}\b`),
		prefixRule("slack-webhook-url", "Slack webhook URL", []string{"hooks.slack.com"},
			`https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_-]{10,}`),

		// An AWS access key ID is not itself secret -- the secret access
		// key is, and that one has no distinguishing shape, so it is
		// caught by the credential-field rule instead. The key ID goes
		// anyway: it names the account and the two are nearly always
		// printed together.
		prefixRule("aws-access-key-id", "AWS access key ID", []string{"AKIA", "ASIA", "ABIA", "ACCA", "A3T"},
			`\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`),

		prefixRule("google-api-key", "Google API key", []string{"AIza"},
			`\bAIza[A-Za-z0-9_-]{35}\b`),
		prefixRule("google-oauth-client-secret", "Google OAuth client secret", []string{"GOCSPX-"},
			`\bGOCSPX-[A-Za-z0-9_-]{20,}\b`),

		// The `T3BlbkFJ` in the middle is base64 for "OpenAI" and is in
		// every key the scheme has issued, old format and new, which
		// makes it a far better anchor than the `sk-` prefix -- `sk-` on
		// its own collides with several other issuers.
		prefixRule("openai-api-key", "OpenAI API key", []string{"T3BlbkFJ"},
			`\bsk-[A-Za-z0-9_-]*T3BlbkFJ[A-Za-z0-9_-]{16,}\b`),
		prefixRule("anthropic-api-key", "Anthropic API key", []string{"sk-ant-"},
			`\bsk-ant-[a-z0-9]+-[A-Za-z0-9_-]{80,}\b`),

		prefixRule("huggingface-token", "Hugging Face token", []string{"hf_"},
			`\bhf_[A-Za-z0-9]{32,}\b`),
		prefixRule("docker-hub-token", "Docker Hub token", []string{"dckr_pat_"},
			`\bdckr_pat_[A-Za-z0-9_-]{20,}\b`),
		prefixRule("npm-token", "npm token", []string{"npm_"},
			`\bnpm_[A-Za-z0-9]{36}\b`),
		prefixRule("pypi-token", "PyPI token", []string{"pypi-AgEI"},
			`\bpypi-AgEI[A-Za-z0-9_-]{50,}\b`),

		prefixRule("stripe-secret-key", "Stripe secret key", []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_"},
			`\b[sr]k_(?:live|test)_[A-Za-z0-9]{20,}\b`),
		prefixRule("sendgrid-api-key", "SendGrid API key", []string{"SG."},
			`\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b`),
		prefixRule("atlassian-api-token", "Atlassian API token", []string{"ATATT3"},
			`\bATATT3[A-Za-z0-9_=+/-]{20,}`),
		prefixRule("digitalocean-token", "DigitalOcean token", []string{"dop_v1_", "doo_v1_", "dor_v1_", "dos_v1_"},
			`\bdo[opsr]_v1_[a-f0-9]{64}\b`),
		prefixRule("age-secret-key", "age secret key", []string{"AGE-SECRET-KEY-1"},
			`\bAGE-SECRET-KEY-1[0-9A-Z]{50,}\b`),
	}
}

// prefixRule builds one issuer-prefix rule. The needles are the literal
// prefixes, which is what makes the prescan over a megabyte of job
// output a handful of substring searches instead of a DFA pass per rule.
func prefixRule(id, what string, needles []string, pattern string) Rule {
	return Rule{
		ID:      id,
		What:    what,
		Needles: needles,
		Pattern: regexp.MustCompile(pattern),
	}
}

// contextRules recognise a credential by where it sits rather than by
// what it looks like: the name of the field holding it, the header it
// follows, its position in a URL. They are what catches an opaque token
// no prefix scheme covers -- which is most of the ones this access point
// handles, since a SciToken's issuer does not stamp a prefix on it.
//
// They run LAST, after the format and issuer rules, because their idea
// of "the value" is everything up to the next delimiter and that is
// usually more than the secret. Running them first would mask a
// recognisable token under a generic label, and would swallow the claims
// the JWT rule exists to preserve.
func contextRules() []Rule {
	return []Rule{
		// A field whose NAME says its value is a credential.
		//
		// This is the rule that covers the case this was built for. An
		// `$_CONDOR_CREDS/<service>.use` file is a JSON object with an
		// `access_token` in it, so a job that cats one, or a library that
		// logs the config it just loaded, is caught by the field name
		// without anyone having to know the issuer's prefix scheme.
		//
		// Three value forms, one per branch: JSON or shell-quoted,
		// single-quoted, and bare up to the next delimiter. The minimum
		// lengths keep `password: ` and `api_key=""` -- a prompt, an
		// unset variable, a placeholder in a template -- out of the
		// count, because a note saying something was redacted when
		// nothing was there sends the reader looking for a leak that did
		// not happen.
		{
			ID:       "credential-field",
			What:     "credential field",
			Needles:  credentialFieldNeedles,
			Anchored: true,
			Pattern: regexp.MustCompile(`(?i)^(?:` + credentialFieldNames + `)"?'?\s*[:=]>?\s*` +
				`(?:"([^"\n]{6,})"|'([^'\n]{6,})'|([^\s,;)}\]"'\n]{8,}))`),
			Groups: []int{1, 2, 3},
			Skip:   skipPlaceholderValue,
		},

		// An Authorization header with its credential, as `curl -v`, a
		// request log or a traced HTTP client prints it. The scheme is
		// kept: "Bearer" and "Basic" and Okta's "SSWS" are different
		// diagnoses, and the scheme alone discloses nothing.
		{
			ID:      "authorization-header",
			What:    "Authorization header",
			Needles: []string{"uthorization", "roxy-Authorization"},
			Pattern: regexp.MustCompile(`(?i)\bauthorization"?'?\s*[:=]\s*` +
				`"?'?(?:bearer|basic|token|ssws|sshs|negotiate|digest|apikey|aws4-hmac-sha256)\s+([^\s"'\n,;]{8,})`),
			Groups: []int{1},
		},

		// A password in a URL's userinfo, which is how a credential ends
		// up in a git remote, a database DSN or a transfer plugin's
		// error message. The username is kept: it identifies the account
		// without being the secret, and it is usually the thing that is
		// wrong.
		{
			ID:   "url-password",
			What: "password in a URL",
			// "://" alone is in any text that mentions a URL, and this
			// pattern then scans all of it. A URL carrying a password
			// also has an "@", which most output does not.
			Needles: []string{"://"},
			Require: []string{"@"},
			Pattern: regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/:@"']+:([^\s/@"']{3,})@`),
			Groups:  []int{1},
		},

		// The credential carried in a signed URL's query string: S3 and
		// GCS presigned URLs, Azure SAS, and the `authz` parameter a
		// Pelican or HTTP transfer plugin appends.
		//
		// Only the one parameter's value goes. The rest of the URL -- the
		// host, the bucket, the object -- says which transfer failed, and
		// is the reason anyone is reading the output.
		{
			ID:      "signed-url-parameter",
			What:    "signed URL credential",
			Needles: signedURLNeedles,
			Pattern: regexp.MustCompile(`(?i)[?&](?:` + signedURLParams + `)=([^&\s"'<>]{8,})`),
			Groups:  []int{1},
		},
	}
}
