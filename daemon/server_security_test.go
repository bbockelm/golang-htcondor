package daemon

import (
	"testing"

	"github.com/bbockelm/cedar/commands"
)

// TestServerSecurityConfigSharedPortID: behind a shared port the server
// config names the daemon's sock id, so FS channel binding checks the id a
// 25.14+ client dialled; on a directly bound socket it names none.
func TestServerSecurityConfigSharedPortID(t *testing.T) {
	d := &Daemon{subsys: "TEST"}
	d.cfg.Store(spConfig(t, "UID_DOMAIN = uid.example\n"))

	sc, err := d.ServerSecurityConfig(int(commands.DC_NOP), "DEFAULT")
	if err != nil {
		t.Fatal(err)
	}
	if sc.SharedPortID != "" {
		t.Errorf("no shared port: SharedPortID = %q, want empty", sc.SharedPortID)
	}

	d.sharedPortName = "collector_123_abcd"
	for _, lvl := range []string{"DEFAULT", "READ", "DAEMON"} {
		sc, err = d.ServerSecurityConfig(int(commands.DC_NOP), lvl)
		if err != nil {
			t.Fatal(err)
		}
		if sc.SharedPortID != "collector_123_abcd" {
			t.Errorf("%s: SharedPortID = %q, want the daemon's sock id", lvl, sc.SharedPortID)
		}
		if sc.UIDDomain != "uid.example" {
			t.Errorf("%s: UIDDomain = %q, want uid.example", lvl, sc.UIDDomain)
		}
	}
}
