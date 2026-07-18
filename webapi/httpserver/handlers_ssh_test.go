package httpserver

import (
	"encoding/json"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Compile-time check that wsControlMsg round-trips through JSON the way
// browser clients will encode it.
func TestWSControlMsgRoundtrip(t *testing.T) {
	cases := []struct {
		name string
		msg  wsControlMsg
		want string
	}{
		{
			name: "resize",
			msg:  wsControlMsg{Type: "resize", Cols: 120, Rows: 40},
			want: `{"type":"resize","cols":120,"rows":40}`,
		},
		{
			name: "signal",
			msg:  wsControlMsg{Type: "signal", Name: "INT"},
			want: `{"type":"signal","name":"INT"}`,
		},
		{
			name: "close",
			msg:  wsControlMsg{Type: "close"},
			want: `{"type":"close"}`,
		},
		{
			name: "exit",
			msg:  wsControlMsg{Type: "exit", Code: 0, Reason: "no-exit-status"},
			want: `{"type":"exit","reason":"no-exit-status"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.msg)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(b) != tc.want {
				t.Errorf("Marshal mismatch:\n got %s\nwant %s", string(b), tc.want)
			}
		})
	}
}

// mapSignal translates the JSON control-frame names into RFC 4254 §6.10
// signal tokens used by golang.org/x/crypto/ssh. Misspellings should map to
// the empty string so that the bridge silently drops them.
func TestMapSignal(t *testing.T) {
	cases := map[string]ssh.Signal{
		"INT":     ssh.SIGINT,
		"SIGINT":  ssh.SIGINT,
		"sigint":  ssh.SIGINT,
		"TERM":    ssh.SIGTERM,
		"QUIT":    ssh.SIGQUIT,
		"HUP":     ssh.SIGHUP,
		"KILL":    ssh.SIGKILL,
		"USR1":    ssh.SIGUSR1,
		"USR2":    ssh.SIGUSR2,
		"":        "",
		"BOGUS":   "",
		"SIGFAKE": "",
	}
	for in, want := range cases {
		if got := mapSignal(in); got != want {
			t.Errorf("mapSignal(%q) = %q, want %q", in, got, want)
		}
	}
}

// translateWaitErr should produce 0 on success, non-zero exit codes for
// ExitError, and a sensible reason for ExitMissingError.
func TestTranslateWaitErr(t *testing.T) {
	if code, reason := translateWaitErr(nil); code != 0 || reason != "" {
		t.Errorf("nil err: got (%d, %q), want (0, \"\")", code, reason)
	}

	missing := &ssh.ExitMissingError{}
	if code, reason := translateWaitErr(missing); code != 0 || reason != "no-exit-status" {
		t.Errorf("ExitMissingError: got (%d, %q), want (0, \"no-exit-status\")", code, reason)
	}

	other := errors.New("transport closed")
	code, reason := translateWaitErr(other)
	if code != -1 || reason == "" {
		t.Errorf("opaque error: got (%d, %q), want (-1, non-empty)", code, reason)
	}
}

// initialPtyDimsFromQuery clamps to defaults outside the [1, 1000] range and
// falls back to (80, 24) when not provided.
func TestInitialPtyDimsFromQuery(t *testing.T) {
	cases := []struct {
		q            map[string][]string
		wantC, wantR int
	}{
		{q: nil, wantC: 80, wantR: 24},
		{q: map[string][]string{"cols": {"120"}, "rows": {"40"}}, wantC: 120, wantR: 40},
		{q: map[string][]string{"cols": {"0"}, "rows": {"40"}}, wantC: 80, wantR: 40},
		{q: map[string][]string{"cols": {"abc"}}, wantC: 80, wantR: 24},
		{q: map[string][]string{"cols": {"100000"}}, wantC: 80, wantR: 24},
	}
	for _, tc := range cases {
		c, r := initialPtyDimsFromQuery(tc.q)
		if c != tc.wantC || r != tc.wantR {
			t.Errorf("initialPtyDimsFromQuery(%v) = (%d, %d), want (%d, %d)", tc.q, c, r, tc.wantC, tc.wantR)
		}
	}
}
