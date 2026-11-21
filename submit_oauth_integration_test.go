package htcondor

import (
	"strings"
	"testing"
)

// The OAuth half of SubmitHash::SetOAuth, held against condor_submit itself.
//
// Two of its rules are not guessable from the submit file, which is why this
// test is the one that decides what the Go side does: the credential's name
// is the SUBMIT KEY's spelling of the service rather than the one
// use_oauth_services wrote, and `<service>_oauth_permissions` is found by
// searching the key rather than by taking the name apart, so a service whose
// own name contains the pattern is cut at the first one.
//
// condor_submit asks the credd for the credentials before it writes the
// job ad, so these cases need both a credd address it can resolve without
// contacting anything and -dry-run:oauth=1, which reports the request and
// carries on. See runCondorSubmitDry.
func TestOAuthServicesNeededMatchesCondorSubmit(t *testing.T) {
	if !condorSubmitAvailable() {
		t.Skip("condor_submit not available")
	}

	tests := []struct {
		name   string
		submit string
	}{
		{"one service", "use_oauth_services = af_x509\n"},
		{"several, comma separated", "use_oauth_services = scitokens, rdrive\n"},
		{"several, space separated", "use_oauth_services = scitokens rdrive\n"},
		{"named twice", "use_oauth_services = scitokens scitokens\n"},
		{"empty token in the list", "use_oauth_services = scitokens,,rdrive\n"},
		{"no services", "use_oauth_services =\n"},
		{"never mentioned", "request_memory = 64\n"},
		{"alternate spelling", "UseOAuthServices = af_x509\n"},
		{"empty primary suppresses the alternate", "use_oauth_services =\nUseOAuthServices = af_x509\n"},
		{"the value is macro expanded", "MYSVC = scitokens\nuse_oauth_services = $(MYSVC)\n"},

		{"handle on permissions", "use_oauth_services = scitokens\nscitokens_oauth_permissions_h1 = read:/a\n"},
		{"handle on resource", "use_oauth_services = scitokens\nscitokens_oauth_resource_h1 = https://x\n"},
		{"handle on options", "use_oauth_services = scitokens\nscitokens_oauth_options_h1 = foo\n"},
		{"two handles", "use_oauth_services = scitokens\nscitokens_oauth_permissions_h1 = a\nscitokens_oauth_permissions_h2 = b\n"},
		{"the same handle twice", "use_oauth_services = scitokens\nscitokens_oauth_permissions_h1 = a\nscitokens_oauth_resource_h1 = https://x\n"},
		{"configured with and without a handle", "use_oauth_services = scitokens\nscitokens_oauth_permissions = a\nscitokens_oauth_permissions_h1 = b\n"},
		{"configured without a handle", "use_oauth_services = scitokens\nscitokens_oauth_permissions = a\n"},
		{"the key names an empty handle", "use_oauth_services = scitokens\nscitokens_oauth_permissions_ = a\n"},
		{"the key has no handle separator", "use_oauth_services = scitokens\nscitokens_oauth_permissionsX = a\n"},
		{"the key's value is empty", "use_oauth_services = scitokens\nscitokens_oauth_permissions_h1 =\n"},
		{"a key for a service not asked for", "use_oauth_services = scitokens\nrdrive_oauth_permissions_h1 = a\n"},

		{"the key's spelling names the service", "use_oauth_services = SciTokens\nscitokens_oauth_permissions_h1 = a\n"},
		{"and when nothing configures it, the command's", "use_oauth_services = SciTokens\n"},
		{"an upper case key", "use_oauth_services = scitokens\nSCITOKENS_OAUTH_PERMISSIONS = a\n"},
		{"sorted without regard to case", "use_oauth_services = Zebra, apple\n"},

		{"a job attribute is not a submit command", "use_oauth_services = scitokens\n+scitokens_oauth_permissions_h1 = \"a\"\n"},
		{"and neither is MY.", "use_oauth_services = scitokens\nMY.scitokens_oauth_permissions_h1 = \"a\"\n"},
		// The one shape where the job-attribute rule is the whole
		// answer: a service whose own name starts with the prefix. The
		// `MY.` key is passed over, so the service keeps the bare name
		// the command gave it instead of taking the handle.
		{"a service named like a job attribute", "use_oauth_services = MY.svc\nMY.svc_oauth_permissions_h1 = \"a\"\n"},
		{"a service named like a forced attribute", "use_oauth_services = +svc\n+svc_oauth_permissions_h1 = \"a\"\n"},
		{"a service whose name holds the pattern", "use_oauth_services = a_oauth_resource_x\na_oauth_resource_x_oauth_permissions = p\n"},

		{"+OAuthServicesNeeded wins", "use_oauth_services = scitokens\n+OAuthServicesNeeded = \"forced\"\n"},
	}

	// A credd address condor_submit can resolve without reaching anything:
	// it locates the credd before -dry-run:oauth=1 takes over, and a bare
	// hostname sends it looking one up.
	env := []string{"_CONDOR_CREDD_HOST=<127.0.0.1:1>"}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			submit := "executable = /bin/sleep\n" + tc.submit + "queue\n"

			want, err := runCondorSubmitDry(submit, env, "-dry-run:oauth=1")
			if err != nil {
				t.Fatalf("condor_submit: %v", err)
			}
			wantServices, wantOK := want.EvaluateAttrString("OAuthServicesNeeded")

			sf, err := ParseSubmitFile(strings.NewReader(submit))
			if err != nil {
				t.Fatalf("ParseSubmitFile: %v", err)
			}
			ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
			if err != nil {
				t.Fatalf("MakeJobAd: %v", err)
			}
			gotServices, gotOK := ad.EvaluateAttrString("OAuthServicesNeeded")

			if gotOK != wantOK {
				t.Fatalf("OAuthServicesNeeded present = %v, condor_submit says %v (got %q, want %q)\nsubmit file:\n%s",
					gotOK, wantOK, gotServices, wantServices, submit)
			}
			if gotServices != wantServices {
				t.Errorf("OAuthServicesNeeded = %q, condor_submit says %q\nsubmit file:\n%s",
					gotServices, wantServices, submit)
			}
		})
	}
}
