package mcpserver

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// A caller whose credential cannot write gets no upload or download URL: the
// URL would act with WRITE, which the caller could not have used themselves.
// A caller whose credential can write gets past the check to the job lookup,
// which in this server has no schedd to answer it.
func TestShareURLToolsRefuseACallerWhoCannotWrite(t *testing.T) {
	s := uploadURLServer(t)
	keyDir := filepath.Dir(s.signingKeyPath)
	callerCtx := func(authz []string) context.Context {
		now := time.Now().Unix()
		tok, err := security.GenerateJWT(keyDir, "POOL", "alice@pool.example", "pool.example", now, now+3600, authz)
		if err != nil {
			t.Fatal(err)
		}
		ctx := htcondor.WithAuthenticatedUser(context.Background(), "alice@pool.example")
		return htcondor.WithSecurityConfig(ctx, &security.SecurityConfig{Token: tok})
	}

	for name, tool := range map[string]func(context.Context, map[string]interface{}) (interface{}, error){
		"create_input_upload_url":    s.toolCreateInputUploadURL,
		"create_output_download_url": s.toolCreateOutputDownloadURL,
	} {
		_, err := tool(callerCtx([]string{"READ"}), map[string]interface{}{"job_id": "1.0"})
		if err == nil || !strings.Contains(err.Error(), "WRITE") {
			t.Errorf("%s with a READ-only credential: err = %v, want a refusal naming WRITE", name, err)
		}
		_, err = tool(callerCtx([]string{"READ", "WRITE"}), map[string]interface{}{"job_id": "1.0"})
		if err == nil || strings.Contains(err.Error(), "authorization") {
			t.Errorf("%s with a READ WRITE credential: err = %v, want only the failed job lookup", name, err)
		}
	}
}
