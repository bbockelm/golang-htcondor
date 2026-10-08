package htcondor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func TestCheckCredsAnswer(t *testing.T) {
	for _, tc := range []struct {
		answer  string
		wantURL string
		wantErr string
	}{
		{answer: "", wantURL: ""},
		{answer: "https://ap.example.org/key/abc", wantURL: "https://ap.example.org/key/abc"},
		{answer: "ERROR: Timed out waiting for local credentials to be generated", wantErr: "Timed out"},
		{answer: "ERROR - SEC_CREDENTIAL_DIRECTORY_OAUTH not configured in condor_credd", wantErr: "not configured"},
	} {
		url, err := checkCredsAnswer(tc.answer)
		if tc.wantErr != "" {
			var refusal *CheckCredsRefusal
			if !errors.As(err, &refusal) || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q: got (%q, %v), want a CheckCredsRefusal containing %q", tc.answer, url, err, tc.wantErr)
			}
			continue
		}
		if err != nil || url != tc.wantURL {
			t.Errorf("%q: got (%q, %v), want (%q, nil)", tc.answer, url, err, tc.wantURL)
		}
	}
}

// The credd's no-service query reply as a local credmon leaves it: a .top
// holding only the user's name, which is not JSON, beside the token.
func TestServiceCredFilesReadsTheListing(t *testing.T) {
	ad := classad.New()
	_ = ad.Set("scitokens.top", int64(1000))
	_ = ad.Set("scitokens.use", int64(2000))
	_ = ad.Set("rdrive.top", int64(1500)) // requested, token not written yet
	_ = ad.Set("box_work.use", int64(3000))
	_ = ad.Set("MyType", "Query")

	files := serviceCredFiles(ad)
	if f := files["scitokens"]; f.top == nil || f.use == nil || f.use.Unix() != 2000 {
		t.Errorf("scitokens: got %+v, want both files with .use at 2000", f)
	}
	if f := files["rdrive"]; f.top == nil || f.use != nil {
		t.Errorf("rdrive: got %+v, want a .top and no .use", f)
	}
	if f := files["box_work"]; f.use == nil {
		t.Errorf("box_work: got %+v, want a .use", f)
	}
	if _, ok := files["MyType"]; ok {
		t.Error("a non-file attribute was read as a credential")
	}
}

func TestInMemoryCheckCreds(t *testing.T) {
	c := NewInMemoryCredd()
	ctx := WithAuthenticatedUser(context.Background(), "alice")

	if url, err := c.CheckCreds(ctx, nil); err != nil || url != "" {
		t.Errorf("no requests: got (%q, %v), want (\"\", nil)", url, err)
	}
	if _, err := c.CheckCreds(ctx, []CredRequest{{Service: "scitokens"}}); err == nil {
		t.Error("a missing credential was reported as present")
	}
	if err := c.PutServiceCred(ctx, CredTypeOAuth, []byte(`{"access_token":"x"}`), "scitokens", "", "", nil); err != nil {
		t.Fatal(err)
	}
	if url, err := c.CheckCreds(ctx, []CredRequest{{Service: "scitokens"}}); err != nil || url != "" {
		t.Errorf("stored credential: got (%q, %v), want (\"\", nil)", url, err)
	}
}
