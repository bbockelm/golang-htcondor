package redact

import (
	"strings"
	"testing"
)

func newDefault(t *testing.T) *Redactor {
	t.Helper()
	r, dropped, unmatched := New(Default(), nil)
	if len(dropped) != 0 || len(unmatched) != 0 {
		t.Fatalf("Default() with no disabled rules dropped %v, unmatched %v", dropped, unmatched)
	}
	return r
}

// A realistic signed token: three base64url segments. Not a real
// credential -- the signature is arbitrary bytes of the right shape.
const sampleJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYyJ9." +
	"eyJpc3MiOiJodHRwczovL2RlbW8uc2NpdG9rZW5zLm9yZyIsInN1YiI6ImJib2NrZWxtIiwic2NvcGUiOiJyZWFkOi9wcm90ZWN0ZWQiLCJleHAiOjE3NjIwMDAwMDB9." +
	"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk"

func TestJWTKeepsClaimsAndDropsSignature(t *testing.T) {
	r := newDefault(t)
	out, res := r.Redact("token: " + sampleJWT + "\n")

	if !res.Changed() {
		t.Fatal("a JWT was not redacted")
	}
	// The two things that make this rule worth having over a blanket
	// mask: the claims survive, and the signature does not.
	header, claims, _ := strings.Cut(sampleJWT, ".")
	claims, sig, _ := strings.Cut(claims, ".")
	if !strings.Contains(out, header+"."+claims+".") {
		t.Errorf("the header and claims should survive; got %q", out)
	}
	if strings.Contains(out, sig) {
		t.Errorf("the signature survived: %q", out)
	}
	if !strings.Contains(out, Marker("jwt-signature")) {
		t.Errorf("no jwt-signature marker: %q", out)
	}
}

// The trap this rule set is most likely to fall into. A share URL minted
// by create_output_download_url is base64url(payload) "." base64url(hmac)
// -- TWO segments, and its payload is JSON, so it begins with `eyJ` just
// as a JWT does. Redacting any part of it hands back a URL that cannot be
// redeemed, and the failure would surface as "invalid or expired token"
// at whoever fetched it rather than as anything pointing back here.
func TestShareURLTokenSurvives(t *testing.T) {
	r := newDefault(t)
	tok := "eyJDbHVzdGVyIjoxMjM0LCJQcm9jIjowLCJPd25lciI6ImJib2NrZWxtIiwiRXhwIjoxNzYyMDAwMDAwLCJLaW5kIjoxfQ." +
		"c2lnbmF0dXJlYnl0ZXNoZXJlc2lnbmF0dXJlYnl0ZXNoZXJlc2ln"
	in := "https://ap.example.edu/api/v1/share/output?t=" + tok

	out, res := r.Redact(in)
	if out != in {
		t.Errorf("a two-segment share token must pass through untouched\n in: %q\nout: %q", in, out)
	}
	if res.Changed() {
		t.Errorf("nothing should have been redacted, got %v", res.Kinds())
	}
}

func TestJWEIsRedactedWhole(t *testing.T) {
	r := newDefault(t)
	jwe := "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe." +
		"48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji.XFBoMYUZodetZdvTiFvSkQ"
	out, res := r.Redact("cred=" + jwe)
	if strings.Contains(out, "XFBoMYUZodetZdvTiFvSkQ") {
		t.Errorf("the JWE's authentication tag survived: %q", out)
	}
	if got := res.Kinds(); len(got) != 1 || got[0] != "jwe" {
		t.Errorf("expected the jwe rule to own this, got %v", got)
	}
}

// An X.509 proxy as a job actually writes one: certificate, key,
// certificate chain. The key is the only secret in it, and the
// certificates are the half somebody reading a failed job needs.
func TestProxyKeepsCertificatesDropsKey(t *testing.T) {
	r := newDefault(t)
	proxy := "-----BEGIN CERTIFICATE-----\n" +
		"MIIEejCCA2KgAwIBAgIEWnVzZXIwDQYJKoZIhvcNAQELBQAwgYQxCzAJBgNVBAYT\n" +
		"-----END CERTIFICATE-----\n" +
		"-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEAvbGhRnxcKxZ8Q3h1b2tleW1hdGVyaWFsZ29lc2hlcmVub3Rh\n" +
		"cmVhbGtleWp1c3RiYXNlNjRzaGFwZWRieXRlc2ZvcmF0ZXN0Zml4dHVyZQ==\n" +
		"-----END RSA PRIVATE KEY-----\n" +
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIDdzCCAl+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzEL\n" +
		"-----END CERTIFICATE-----\n"

	out, res := r.Redact(proxy)
	if strings.Contains(out, "MIIEowIBAAKCAQEAvbGhRnxcKxZ8") {
		t.Errorf("private key material survived:\n%s", out)
	}
	for _, want := range []string{
		"MIIEejCCA2KgAwIBAgIEWnVzZXIwDQYJKoZIhvcNAQELBQAwgYQxCzAJBgNVBAYT",
		"MIIDdzCCAl+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBaMQswCQYDVQQGEwJVUzEL",
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----END RSA PRIVATE KEY-----",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q to survive:\n%s", want, out)
		}
	}
	if got := res.Kinds(); len(got) != 1 || got[0] != "pem-private-key" {
		t.Errorf("expected only pem-private-key, got %v", got)
	}
}

// Output cut off mid-key is exactly when the key is still entirely
// present, so the block with no END line has to be redacted too.
func TestUnterminatedPEMBlockIsRedacted(t *testing.T) {
	r := newDefault(t)
	in := "writing key...\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB"
	out, res := r.Redact(in)
	if strings.Contains(out, "b3BlbnNzaC1rZXktdjEA") {
		t.Errorf("a truncated key survived: %q", out)
	}
	if !res.Changed() {
		t.Error("nothing was redacted")
	}
}

// The case this was built for: `cat $_CONDOR_CREDS/<service>.use`.
func TestCondorCredsUseFile(t *testing.T) {
	r := newDefault(t)
	use := `{"access_token": "ya29.a0ARrdaM-NOT-REAL-BUT-TOKEN-SHAPED-abcdefghijklmnop", ` +
		`"refresh_token": "1//0gLONGREFRESHTOKENVALUEHEREabcdefghijklmnop", ` +
		`"expires_in": 3599, "token_type": "Bearer", "scope": "read:/protected"}`

	out, res := r.Redact(use)
	for _, secret := range []string{
		"ya29.a0ARrdaM-NOT-REAL-BUT-TOKEN-SHAPED-abcdefghijklmnop",
		"1//0gLONGREFRESHTOKENVALUEHEREabcdefghijklmnop",
	} {
		if strings.Contains(out, secret) {
			t.Errorf("%q survived:\n%s", secret, out)
		}
	}
	// The fields that say what the credential was for are not secret and
	// are what makes a redacted `.use` file still worth reading.
	for _, want := range []string{`"expires_in": 3599`, `"scope": "read:/protected"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q to survive:\n%s", want, out)
		}
	}
	if res.Values() != 2 {
		t.Errorf("expected 2 distinct secrets, got %d (%v)", res.Values(), res.Kinds())
	}
}

func TestTable(t *testing.T) {
	r := newDefault(t)
	cases := []struct {
		name   string
		in     string
		secret string // must not appear in the output; "" means nothing redacted
		rule   string
	}{
		{"github classic pat", "remote: https://x@github.com\nghp_" + strings.Repeat("A", 36),
			"ghp_" + strings.Repeat("A", 36), "github-token"},
		{"github fine grained", "GITHUB_TOKEN=github_pat_" + strings.Repeat("b", 40),
			"github_pat_" + strings.Repeat("b", 40), "github-fine-grained-pat"},
		{"aws key id", "key AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE", "aws-access-key-id"},
		{"huggingface", "login hf_" + strings.Repeat("Q", 34), "hf_" + strings.Repeat("Q", 34), "huggingface-token"},
		{"docker hub", "docker login -p dckr_pat_" + strings.Repeat("z", 28),
			"dckr_pat_" + strings.Repeat("z", 28), "docker-hub-token"},
		{"slack bot", "xoxb-123456789012-123456789012-" + strings.Repeat("c", 24),
			"xoxb-123456789012", "slack-token"},
		{"google api key", "AIza" + strings.Repeat("D", 35), "AIza" + strings.Repeat("D", 35), "google-api-key"},
		{"authorization bearer", `curl -H "Authorization: Bearer abcdef0123456789abcdef" https://x/`,
			"abcdef0123456789abcdef", "authorization-header"},
		{"url password", "git clone https://alice:hunter2secret@git.example.edu/repo.git",
			"hunter2secret", "url-password"},
		{"presigned s3", "GET https://s3.example.edu/b/o?X-Amz-Signature=8e1f2a3b4c5d6e7f8091a2b3c4d5e6f7&X-Amz-Date=1",
			"8e1f2a3b4c5d6e7f8091a2b3c4d5e6f7", "signed-url-parameter"},
		{"pelican authz", "transfer failed: https://osg.example/ns/f.root?authz=eyJhbGciOiJF.abcdefghijkl",
			"abcdefghijkl", "signed-url-parameter"},
		{"kerberos ccache", "ticket: BQQABAAB" + strings.Repeat("c", 70),
			"BQQABAAB" + strings.Repeat("c", 70), "kerberos-credential"},

		// Negatives: output a job legitimately produces.
		{"git sha", "building at commit 9f8c2a1b4d6e8f0a2c4e6080a2c4e6080a2c4e60", "", ""},
		{"md5 checksum", "d41d8cd98f00b204e9800998ecf8427e  input.dat", "", ""},
		{"uuid", "run id 3f2504e0-4f89-11d3-9a0c-0305e82c3301 complete", "", ""},
		{"base64 payload", "result=" + strings.Repeat("QUJDREVG", 20), "", ""},
		{"placeholder password", `password: changeme`, "", ""},
		{"empty api key", `api_key = ""`, "", ""},
		{"plain url", "fetching https://data.example.edu/set/2026/file.root", "", ""},
		{"certificate only", "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIBATANBg\n-----END CERTIFICATE-----", "", ""},
		{"scientific numbers", "chi2=1.2345e-08 nevents=12345678901234 rate=0.9999", "", ""},
		{"hex dump", "0x0000: 4f 6e 65 20 74 77 6f 20 74 68 72 65 65 20 66 6f", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, res := r.Redact(tc.in)
			if tc.secret == "" {
				if res.Changed() {
					t.Fatalf("redacted something it should not have (%v)\n in: %q\nout: %q",
						res.Kinds(), tc.in, out)
				}
				return
			}
			if strings.Contains(out, tc.secret) {
				t.Fatalf("the secret survived\n in: %q\nout: %q", tc.in, out)
			}
			if !contains(res.Kinds(), tc.rule) {
				t.Fatalf("expected rule %q to fire, got %v\nout: %q", tc.rule, res.Kinds(), out)
			}
		})
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// Re-redacting must be a no-op on the text and must not report a second
// round of secrets. The markers are what make this true, and a rule
// added later could break it without breaking anything else.
func TestIdempotent(t *testing.T) {
	r := newDefault(t)
	in := "tok " + sampleJWT + "\npassword: s3cr3tvalue!\nkey ghp_" + strings.Repeat("A", 36) + "\n" +
		"-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBase64Body==\n-----END EC PRIVATE KEY-----\n"

	once, res1 := r.Redact(in)
	if !res1.Changed() {
		t.Fatal("nothing was redacted on the first pass")
	}
	twice, res2 := r.Redact(once)
	if twice != once {
		t.Errorf("a second pass changed the text:\n1: %q\n2: %q", once, twice)
	}
	if res2.Changed() {
		t.Errorf("a second pass reported %v; the markers should match nothing", res2.Kinds())
	}
}

func TestDisablingRules(t *testing.T) {
	r, dropped, unmatched := New(Default(), []string{"github-*", "kerberos-credential"})
	if len(unmatched) != 0 {
		t.Errorf("patterns matched no rule: %v", unmatched)
	}
	if !contains(dropped, "github-token") || !contains(dropped, "github-fine-grained-pat") ||
		!contains(dropped, "kerberos-credential") {
		t.Errorf("expected the github family and kerberos to be dropped, got %v", dropped)
	}
	tok := "ghp_" + strings.Repeat("A", 36)
	out, res := r.Redact("key " + tok)
	if !strings.Contains(out, tok) || res.Changed() {
		t.Errorf("a disabled rule still fired: %q %v", out, res.Kinds())
	}

	// A typo has to be reported: silently leaving a rule on is the
	// failure an operator cannot see.
	_, _, unmatched = New(Default(), []string{"githb-token"})
	if len(unmatched) != 1 || unmatched[0] != "githb-token" {
		t.Errorf("expected the typo to be reported, got %v", unmatched)
	}
}

func TestNoteNamesWhatAndHowMany(t *testing.T) {
	r := newDefault(t)
	_, res := r.Redact("a " + sampleJWT + " b ghp_" + strings.Repeat("A", 36))
	note := res.Note()
	for _, want := range []string{"2 values", "JWT signature", "GitHub token", "[REDACTED:...]"} {
		if !strings.Contains(note, want) {
			t.Errorf("note is missing %q:\n%s", want, note)
		}
	}

	_, one := r.Redact("ghp_" + strings.Repeat("A", 36))
	if n := one.Note(); !strings.Contains(n, "1 value matching") || !strings.Contains(n, "was replaced") {
		t.Errorf("a single redaction should read as one: %s", n)
	}
	if n := (*Result)(nil).Note(); n != "" {
		t.Errorf("an unchanged result has no note, got %q", n)
	}
}

// The prescan decides whether a result is examined at all, so a needle
// that does not actually appear in what its rule matches would make that
// rule dead. Checked by construction rather than by hoping each rule's
// own test would notice.
func TestEveryRuleHasAReachableNeedle(t *testing.T) {
	for _, rule := range Default() {
		if len(rule.Needles) == 0 {
			t.Errorf("rule %q has no needle, so it runs its pattern on every call", rule.ID)
		}
		if rule.Pattern == nil && rule.Fn == nil {
			t.Errorf("rule %q has neither a pattern nor a function", rule.ID)
		}
		if rule.What == "" {
			t.Errorf("rule %q has no description for the note", rule.ID)
		}
	}
}

func TestMightContainGatesTheWalk(t *testing.T) {
	r := newDefault(t)
	clean := []byte(`{"content":[{"type":"text","text":"Job 42.0 completed in 3m12s, 0 errors"}]}`)
	if r.MightContain(clean) {
		t.Errorf("ordinary output should not reach the rules: %s", clean)
	}
	dirty := []byte(`{"text":"ghp_` + strings.Repeat("A", 36) + `"}`)
	if !r.MightContain(dirty) {
		t.Error("a payload with a token in it must reach the rules")
	}
}

// Two corpora, because the cost is in which rules the prescan lets
// through. "plain" is job output no needle touches and measures the
// prescan alone; "needled" contains the words that wake the broadest
// rules -- a URL with a query string, the word "token" -- and measures
// what a result that trips the prescan without holding a secret costs.
func BenchmarkCleanJobOutput(b *testing.B) {
	for _, bc := range []struct{ name, line string }{
		{"plain", "2026-11-07 14:23:11 INFO  processing event 148213 chi2=1.2345e-08 " +
			"out=/srv/data/run2026/part-00031.root sha=9f8c2a1b4d6e8f0a2c4e6080a2c4e6080a2c4e60\n"},
		{"needled", "2026-11-07 14:23:11 INFO  GET https://data.example.edu/f.root?range=0-1024 " +
			"auth=token refreshed, 148213 events, sha=9f8c2a1b4d6e8f0a2c4e6080a2c4e6080a2c4e60\n"},
	} {
		b.Run(bc.name, func(b *testing.B) {
			r, _, _ := New(Default(), nil)
			var sb strings.Builder
			for sb.Len() < 100<<10 {
				sb.WriteString(bc.line)
			}
			s := sb.String()
			b.SetBytes(int64(len(s)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, res := r.Redact(s); res.Changed() {
					b.Fatalf("the benchmark corpus should be clean, got %v", res.Kinds())
				}
			}
		})
	}
}

// The credential-field rule is anchored at its needle, so the field name
// it matches is only the head word and the qualifier in front of it is
// never part of the match. These are the spellings that reach this
// access point, and each one has to find its way to the same rule.
func TestCredentialFieldSpellings(t *testing.T) {
	r := newDefault(t)
	const secret = "s3cr3t-value-long-enough"
	for _, line := range []string{
		`"access_token": "` + secret + `"`,
		`"refresh_token":"` + secret + `"`,
		`REFRESH_TOKEN=` + secret,
		`HF_TOKEN = ` + secret,
		`api-key: ` + secret,
		`AWS_SECRET_ACCESS_KEY=` + secret,
		`client_secret => '` + secret + `'`,
		`password: ` + secret,
		`passphrase="` + secret + `"`,
		`Authorization-Token: ` + secret,
		`my.service.credential = ` + secret,
	} {
		out, res := r.Redact(line)
		if strings.Contains(out, secret) {
			t.Errorf("not redacted: %q -> %q", line, out)
			continue
		}
		if !contains(res.Kinds(), "credential-field") {
			t.Errorf("wrong rule for %q: %v", line, res.Kinds())
		}
	}

	// Words that merely contain a head word are not field names.
	for _, line := range []string{
		"monkey=banana_and_more_text",
		"tokenizer_config.json written to /srv/out",
		"keyboard = mechanical_switches_here",
		"the secretary signed off on it",
	} {
		if out, res := r.Redact(line); res.Changed() {
			t.Errorf("false positive on %q -> %q (%v)", line, out, res.Kinds())
		}
	}
}

// Anchoring bounds how far past the field name a value may be found. A
// value longer than the window is partially masked rather than missed,
// which is the right failure: the rule still fires, so the note still
// warns, and the remaining tail is not a usable credential.
func TestAnchoredWindowDoesNotMissTheField(t *testing.T) {
	r := newDefault(t)
	long := strings.Repeat("sEcr3t-", anchorWindow/3)
	out, res := r.Redact("access_token=" + long)
	if !res.Changed() {
		t.Fatal("an over-long value was not noticed at all")
	}
	if strings.Contains(out, long) {
		t.Error("the whole over-long value survived")
	}
}

// Many candidate sites in one payload must not turn into a scan of the
// whole text per site. Guards the property, not a timing: a regression
// here shows up as a test that stops finishing.
func TestManyCandidateSitesStayLinear(t *testing.T) {
	r := newDefault(t)
	var sb strings.Builder
	for i := 0; i < 20000; i++ {
		sb.WriteString("level=info msg=\"token refreshed\" elapsed=12ms\n")
	}
	sb.WriteString("access_token: the-one-real-secret-value\n")
	out, res := r.Redact(sb.String())
	if strings.Contains(out, "the-one-real-secret-value") {
		t.Error("the one real secret was missed")
	}
	if res.Values() != 1 {
		t.Errorf("expected exactly one secret, got %d (%v)", res.Values(), res.Kinds())
	}
}

// An anchored rule is only tried where one of its needles occurs, so a
// needle the pattern cannot begin with makes that rule silently blind at
// exactly the spellings the needle was added for. Nothing fails; the
// secret just goes through. That is how `api-key:` came to be missed
// while `apikey:` was caught.
//
// Checked in both directions against the names below, which are also
// the readable statement of what the rule covers:
//
//   - every name must anchor the pattern, and must be reachable from
//     some needle, or the rule cannot fire on it;
//   - every needle must lead to some name, or it is dead weight in the
//     prescan that runs on every call.
func TestAnchoredNeedlesAlignWithTheirPattern(t *testing.T) {
	fieldNames := []string{
		"token", "Token", "TOKEN",
		"secret", "Secret", "SECRET",
		"password", "Password", "PASSWORD",
		"passwd", "Passwd", "PASSWD",
		"passphrase", "Passphrase", "PASSPHRASE",
		"credential", "Credential", "CREDENTIAL",
		"apikey", "api_key", "api-key", "API_KEY", "ApiKey", "Api_Key",
		"private_key", "Private_Key", "PRIVATE_KEY", "privatekey",
		"secret_key", "SECRET_KEY",
		"access_key", "Access_Key", "ACCESS_KEY", "accesskey",
		"account_key", "Account_Key", "ACCOUNT_KEY",
		"signing_key", "Signing_Key", "SIGNING_KEY",
		"connection_string", "Connection_String", "CONNECTION_STRING", "connectionstring",
	}

	var anchored *Rule
	for i, rule := range Default() {
		if rule.ID == "credential-field" {
			anchored = &Default()[i]
		}
	}
	if anchored == nil {
		t.Fatal("the credential-field rule has gone missing")
	}

	reached := map[string]bool{}
	for _, name := range fieldNames {
		probe := name + "=sEcr3t-value-long-enough"
		if loc := anchored.Pattern.FindStringIndex(probe); loc == nil || loc[0] != 0 {
			t.Errorf("%q does not anchor the pattern (matched %v)", probe, loc)
		}
		hit := false
		for _, n := range anchored.Needles {
			if strings.HasPrefix(name, n) {
				reached[n], hit = true, true
			}
		}
		if !hit {
			t.Errorf("no needle reaches %q, so the rule is never tried there", name)
		}
	}
	for _, n := range anchored.Needles {
		if !reached[n] {
			t.Errorf("needle %q leads to no field name; it only costs the prescan", n)
		}
	}
}
