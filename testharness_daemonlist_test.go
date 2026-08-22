package htcondor

import "testing"

// TestDaemonListHasSchedd covers the readiness gate: the harness waits
// for a schedd ad only when its config actually runs one. Getting this
// wrong either reintroduces the startup race (false) or hangs a
// schedd-less harness for the full timeout (true).
func TestDaemonListHasSchedd(t *testing.T) {
	const base = "DAEMON_LIST = MASTER, COLLECTOR, SCHEDD, NEGOTIATOR, STARTD\n"

	cases := []struct {
		name   string
		config string
		want   bool
	}{
		{"default harness config", base, true},
		{"no daemon list at all", "SPOOL = /tmp\n", false},
		{
			"extra config appends via $(DAEMON_LIST)",
			base + "\nDAEMON_LIST = $(DAEMON_LIST) TESTGODAEMON\n",
			true,
		},
		{
			"extra config replaces the list, keeping the schedd",
			base + "\nDAEMON_LIST = MASTER, COLLECTOR, SCHEDD, NEGOTIATOR, STARTD, TESTDAEMON\n",
			true,
		},
		{
			"extra config replaces the list, dropping the schedd",
			base + "\nDAEMON_LIST = MASTER, COLLECTOR, SHARED_PORT, HTTP_API\n",
			false,
		},
		{
			"commented-out override does not count",
			base + "\n# DAEMON_LIST = MASTER, COLLECTOR\n",
			true,
		},
		{
			"schedd-less base extended without a schedd",
			"DAEMON_LIST = MASTER, COLLECTOR\nDAEMON_LIST = $(DAEMON_LIST) STARTD\n",
			false,
		},
		{"case-insensitive", "daemon_list = master, schedd\n", true},
	}
	for _, tc := range cases {
		if got := daemonListHasSchedd(tc.config); got != tc.want {
			t.Errorf("%s: daemonListHasSchedd() = %v, want %v", tc.name, got, tc.want)
		}
	}
}
