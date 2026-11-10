package httpserver

import (
	"errors"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/reservation"
)

// The case that matters is a pool where nothing published a capability:
// every command then goes as this access point and is refused by
// execute points that never agreed to take orders from it, and the
// refusal is indistinguishable from an expired capability. It has to be
// an error, not a warning among warnings.
func TestCapabilityReportRanksTheSilentFailureHighest(t *testing.T) {
	cases := []struct {
		name  string
		caps  reservation.Capabilities
		level capabilityLevel
		says  []string
	}{
		{
			name:  "every machine published one",
			caps:  reservation.Capabilities{Machines: 12, WithCapability: 12, Usable: 12},
			level: capabilityOK,
			says:  []string{"all 12"},
		},
		{
			name:  "none did",
			caps:  reservation.Capabilities{Machines: 12, Usable: 12},
			level: capabilityBroken,
			says:  []string{"none of 12", "ADMINISTRATOR at the collector", "SEC_ENABLE_REMOTE_ADMINISTRATION"},
		},
		{
			name:  "some did",
			caps:  reservation.Capabilities{Machines: 12, WithCapability: 9, Usable: 12},
			level: capabilityWarn,
			says:  []string{"9 of 12"},
		},
		{
			name:  "nothing matched the constraint",
			caps:  reservation.Capabilities{},
			level: capabilityWarn,
			says:  []string{"no execute point matched"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			level, msg := capabilityReport(c.caps)
			if level != c.level {
				t.Fatalf("level = %d, want %d (%q)", level, c.level, msg)
			}
			for _, want := range c.says {
				if !strings.Contains(msg, want) {
					t.Fatalf("message %q does not mention %q", msg, want)
				}
			}
		})
	}
}

// Logged on change, not every read: the pool is re-read every few
// minutes and a steady state is not news. But the first reading is
// always news, and so is going back to healthy.
func TestCapabilitiesAreReportedOnChangeOnly(t *testing.T) {
	var said []string
	h := &Handler{}
	report := h.capabilityReporter(func(_ capabilityLevel, msg string) { said = append(said, msg) })

	healthy := reservation.Capabilities{Machines: 3, WithCapability: 3, Usable: 3}
	broken := reservation.Capabilities{Machines: 3, Usable: 3}

	report(healthy)
	if len(said) != 1 {
		t.Fatalf("the first reading said %d things, want 1", len(said))
	}
	report(healthy)
	report(healthy)
	if len(said) != 1 {
		t.Fatalf("an unchanged reading was reported again: %v", said)
	}
	report(broken)
	if len(said) != 2 {
		t.Fatalf("a pool that lost every capability was not reported: %v", said)
	}
	report(broken)
	if len(said) != 2 {
		t.Fatalf("the broken reading was repeated: %v", said)
	}
	report(healthy)
	if len(said) != 3 {
		t.Fatalf("recovery was not reported: %v", said)
	}
}

func TestAFailedReadIsAlwaysReported(t *testing.T) {
	var said []string
	h := &Handler{}
	report := h.capabilityReporter(func(_ capabilityLevel, msg string) { said = append(said, msg) })

	report(reservation.Capabilities{Machines: 3, WithCapability: 3, Usable: 3})
	n := len(said)
	report(reservation.Capabilities{Err: errors.New("collector is down")})
	if len(said) <= n {
		t.Fatalf("a failed read said nothing: %v", said)
	}
}
