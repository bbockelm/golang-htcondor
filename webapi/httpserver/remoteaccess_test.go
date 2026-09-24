package httpserver

import (
	"context"
	"strings"
	"testing"
)

// The universes the schedd refuses, and the ones it does not. LOCAL
// (12) is the one worth pinning: it looks like a scheduler-universe job
// (it runs on the access point) but it runs under a starter, so tail
// and ssh both work and refusing it would break a working feature.
func TestJobUniverseRefusesRemoteAccess(t *testing.T) {
	cases := []struct {
		name     string
		universe int64
		want     bool
	}{
		{"scheduler", 7, true},
		{"grid", 9, true},
		{"vanilla", 5, false},
		{"mpi", 8, false},
		{"java", 10, false},
		{"parallel", 11, false},
		{"local", 12, false},
		{"vm", 13, false},
		{"docker", 14, false},
		{"unset", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := jobUniverseRefusesRemoteAccess(tc.universe); got != tc.want {
				t.Errorf("jobUniverseRefusesRemoteAccess(%d) = %v, want %v", tc.universe, got, tc.want)
			}
		})
	}
}

// The message is the whole point of the check -- the operation was
// already going to fail. Each case asserts the facts a reader needs:
// which job, which universe, why there is nothing to reach, and (for
// peek on a scheduler job) where the output actually is.
func TestRemoteAccessRefusalMessage(t *testing.T) {
	cases := []struct {
		name     string
		op       string
		universe int64
		want     []string
		absent   []string
	}{
		{
			name:     "peek scheduler names the spool and the endpoints",
			op:       "peek",
			universe: 7,
			want: []string{
				"Job 42.1", "scheduler-universe", "JobUniverse=7",
				"not under a starter", "nothing to tail",
				"written in place", "spool",
				"/api/v1/jobs/42.1/stdout", "/stderr", "/files/{name}",
			},
			// The generic peek failure says this, and for a job that is
			// running and always will be refused it is a lie.
			absent: []string{"may not be running yet"},
		},
		{
			name:     "peek grid does not promise a spool",
			op:       "peek",
			universe: 9,
			want: []string{
				"Job 42.1", "grid-universe", "JobUniverse=9",
				"remote batch system", "no starter",
			},
			absent: []string{"spool", "/files/{name}", "may not be running yet"},
		},
		{
			name:     "ssh scheduler says a starter is what is missing",
			op:       "ssh",
			universe: 7,
			want:     []string{"Job 42.1", "JobUniverse=7", "condor_ssh_to_job", "starter"},
			absent:   []string{"spool"},
		},
		{
			name:     "ssh grid",
			op:       "ssh",
			universe: 9,
			want:     []string{"Job 42.1", "JobUniverse=9", "condor_ssh_to_job", "remote batch system"},
			absent:   []string{"spool"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := remoteAccessRefusalMessage(tc.op, 42, 1, tc.universe)
			for _, want := range tc.want {
				if !strings.Contains(msg, want) {
					t.Errorf("message does not mention %q: %s", want, msg)
				}
			}
			for _, bad := range tc.absent {
				if strings.Contains(msg, bad) {
					t.Errorf("message should not mention %q: %s", bad, msg)
				}
			}
		})
	}
}

// Unknown is not refused. The lookup exists to improve an error
// message; a schedd that cannot be reached must leave the operation to
// fail (or succeed) on its own terms rather than being turned into a
// refusal of something that would have worked.
func TestRefuseRemoteAccessByUniverseFailsOpen(t *testing.T) {
	s := sshFailureTestServer(t)
	// No queue behind the configured address, so the query errors out.
	msg, refuse := s.refuseRemoteAccessByUniverse(context.Background(), "peek", 1, 0)
	if refuse {
		t.Errorf("refused a job whose universe could not be read: %s", msg)
	}
}
