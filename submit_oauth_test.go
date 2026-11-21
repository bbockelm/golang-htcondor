package htcondor

import (
	"strings"
	"testing"
)

// OAuthServicesNeeded without condor_submit, so the rules are still checked
// where it is not installed. Every expectation here was taken from
// condor_submit; TestOAuthServicesNeededMatchesCondorSubmit is what keeps
// them honest, and a case added here belongs there too.
func TestOAuthServicesNeeded(t *testing.T) {
	tests := []struct {
		name   string
		submit string
		want   string // "" means the attribute is absent
	}{
		{"one service", "use_oauth_services = af_x509\n", "af_x509"},
		{"sorted, without regard to case", "use_oauth_services = Zebra, apple\n", "apple,Zebra"},
		{"named twice", "use_oauth_services = scitokens scitokens\n", "scitokens"},
		{"no services", "use_oauth_services =\n", ""},
		{"never mentioned", "request_memory = 64\n", ""},
		{"alternate spelling", "UseOAuthServices = af_x509\n", "af_x509"},
		{"empty primary suppresses the alternate", "use_oauth_services =\nUseOAuthServices = af_x509\n", ""},
		{"the value is macro expanded", "MYSVC = scitokens\nuse_oauth_services = $(MYSVC)\n", "scitokens"},

		{"a handle renames the credential", "use_oauth_services = scitokens\nscitokens_oauth_permissions_h1 = read:/a\n", "scitokens*h1"},
		{"two handles are two credentials", "use_oauth_services = scitokens\nscitokens_oauth_permissions_h1 = a\nscitokens_oauth_resource_h2 = https://x\n", "scitokens*h1,scitokens*h2"},
		{"configured with and without a handle", "use_oauth_services = scitokens\nscitokens_oauth_permissions = a\nscitokens_oauth_permissions_h1 = b\n", "scitokens,scitokens*h1"},
		{"a key for a service not asked for", "use_oauth_services = scitokens\nrdrive_oauth_permissions_h1 = a\n", "scitokens"},
		{"the key's spelling names the service", "use_oauth_services = SciTokens\nscitokens_oauth_permissions_h1 = a\n", "scitokens*h1"},
		{"and when nothing configures it, the command's", "use_oauth_services = SciTokens\n", "SciTokens"},
		{"a job attribute is not a submit command", "use_oauth_services = MY.svc\nMY.svc_oauth_permissions_h1 = \"a\"\n", "MY.svc"},
		{"a service whose name holds the pattern", "use_oauth_services = a_oauth_resource_x\na_oauth_resource_x_oauth_permissions = p\n", "a_oauth_resource_x"},

		{"+OAuthServicesNeeded wins", "use_oauth_services = scitokens\n+OAuthServicesNeeded = \"forced\"\n", "forced"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			submit := "executable = /bin/sleep\n" + tc.submit + "queue\n"
			sf, err := ParseSubmitFile(strings.NewReader(submit))
			if err != nil {
				t.Fatalf("ParseSubmitFile: %v", err)
			}
			ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
			if err != nil {
				t.Fatalf("MakeJobAd: %v", err)
			}

			got, ok := ad.EvaluateAttrString("OAuthServicesNeeded")
			if tc.want == "" {
				if ok {
					t.Fatalf("OAuthServicesNeeded = %q, want the attribute to be absent", got)
				}
				return
			}
			if !ok {
				t.Fatalf("OAuthServicesNeeded is absent, want %q", tc.want)
			}
			if got != tc.want {
				t.Errorf("OAuthServicesNeeded = %q, want %q", got, tc.want)
			}
		})
	}
}

// The attribute is a string. A job whose OAuthServicesNeeded is a bare
// identifier reaches the shadow as an expression to evaluate rather than a
// list of service names.
func TestOAuthServicesNeededIsAString(t *testing.T) {
	sf, err := ParseSubmitFile(strings.NewReader("executable = /bin/sleep\nuse_oauth_services = scitokens\nqueue\n"))
	if err != nil {
		t.Fatalf("ParseSubmitFile: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, nil)
	if err != nil {
		t.Fatalf("MakeJobAd: %v", err)
	}
	if got := ad.String(); !strings.Contains(got, `OAuthServicesNeeded = "scitokens"`) {
		t.Errorf("job ad does not carry OAuthServicesNeeded as a string:\n%s", got)
	}
}
