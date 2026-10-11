package sshgateway

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/jobid"
)

// A gateway fronting several access points reads the codec's form as the
// SSH user: OpenSSH splits user@host at the LAST "@", so
// "123.0@ap1.example.org@gateway" arrives as "123.0@ap1.example.org".
func TestParseTargetWithCodec(t *testing.T) {
	codec := jobid.Default()
	for _, c := range []struct {
		user    string
		job     bool
		schedd  string
		cluster int
		proc    int
		name    string
	}{
		{user: "123.4@ap1.example.org", job: true, schedd: "ap1.example.org", cluster: 123, proc: 4},
		{user: "123@jobs@ap2.example.org", job: true, schedd: "jobs@ap2.example.org", cluster: 123},
		{user: "123.4", job: true, cluster: 123, proc: 4}, // incomplete: as without a codec
		{user: "+work", name: "work"},
		{user: "alice@example.org", name: DefaultSessionName}, // not a job id: a local login
		{user: "bbockelm", name: DefaultSessionName},
	} {
		got, err := ParseTargetWith(codec, c.user)
		if err != nil {
			t.Errorf("%q: %v", c.user, err)
			continue
		}
		if got.IsJob() != c.job || got.Schedd != c.schedd || got.Cluster != c.cluster || got.Proc != c.proc || got.Name != c.name {
			t.Errorf("%q = %+v", c.user, got)
		}
	}
	// Without a codec, nothing changes: the AP form is not a job id.
	if got, _ := ParseTargetWith(nil, "123.4@ap1.example.org"); got.IsJob() || got.Schedd != "" {
		t.Errorf("no codec: %+v", got)
	}
	if got, _ := ParseTargetWith(codec, "123.4@ap1.example.org"); got.String() != "job 123.4 on ap1.example.org" {
		t.Errorf("String = %q", got.String())
	}
}
