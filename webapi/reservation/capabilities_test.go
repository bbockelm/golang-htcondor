package reservation

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/startd"
)

// An execute point that publishes no administrative capability is still
// commanded -- with this access point's own credentials -- and on most
// pools refused. The refusal is indistinguishable from a capability
// that was used and rejected, so the only place the difference can be
// seen is here, where the access point knows which it sent.

// noCapAd is capAd without the capability attribute.
func noCapAd() string {
	return `Name = "slot1@wn09"
Machine = "wn09"
MyAddress = "<127.0.0.1:19619>"
PartitionableSlot = true`
}

func reloadWith(t *testing.T, require bool, adText ...string) Capabilities {
	t.Helper()
	q := &fakeQuerier{ads: ads(t, adText...)}
	var got Capabilities
	a := &PoolActuator{Query: q, RequireCapability: require, OnReload: func(c Capabilities) { got = c }}
	if err := a.reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if from := a.Refreshed(); from.Machines != got.Machines || from.WithCapability != got.WithCapability {
		t.Fatalf("Refreshed reports %+v but OnReload said %+v", from, got)
	}
	return got
}

func TestCapabilitiesCountsWhoPublishedOne(t *testing.T) {
	c := reloadWith(t, false, capAd(), noCapAd())
	if c.Machines != 2 {
		t.Fatalf("Machines = %d, want 2", c.Machines)
	}
	if c.WithCapability != 1 {
		t.Fatalf("WithCapability = %d, want 1", c.WithCapability)
	}
	if c.Usable != 2 {
		t.Fatalf("Usable = %d, want both: without RequireCapability the second is still commanded", c.Usable)
	}
	if !c.Degraded() {
		t.Fatal("a pool where one machine published no capability is not reported as degraded")
	}
	if c.At.IsZero() {
		t.Fatal("no read time recorded")
	}
}

func TestCapabilitiesWhenEveryMachinePublishedOne(t *testing.T) {
	c := reloadWith(t, false, capAd())
	if c.Machines != 1 || c.WithCapability != 1 {
		t.Fatalf("got %+v, want one machine with a capability", c)
	}
	if c.Degraded() {
		t.Fatal("a fully capable pool is reported as degraded")
	}
}

func TestCapabilitiesWhenNobodyPublishedOne(t *testing.T) {
	c := reloadWith(t, false, noCapAd())
	if c.Machines != 1 {
		t.Fatalf("Machines = %d, want 1", c.Machines)
	}
	if c.WithCapability != 0 {
		t.Fatalf("WithCapability = %d, want 0", c.WithCapability)
	}
	if !c.Degraded() {
		t.Fatal("a pool publishing no capabilities at all is not reported as degraded")
	}
}

// With RequireCapability the machine is dropped rather than commanded
// as this process, so Usable and WithCapability agree.
func TestRequireCapabilityDropsTheMachineInstead(t *testing.T) {
	c := reloadWith(t, true, capAd(), noCapAd())
	if c.Machines != 2 {
		t.Fatalf("Machines = %d, want both counted", c.Machines)
	}
	if c.WithCapability != 1 || c.Usable != 1 {
		t.Fatalf("got WithCapability=%d Usable=%d, want 1 and 1", c.WithCapability, c.Usable)
	}
	if c.Err == nil || !strings.Contains(c.Err.Error(), "wn09") {
		t.Fatalf("Err = %v, want it to name the machine that published none", c.Err)
	}
}

func TestCapabilitiesReportsAFailedRead(t *testing.T) {
	q := &fakeQuerier{err: errors.New("collector is down")}
	var got Capabilities
	a := &PoolActuator{Query: q, OnReload: func(c Capabilities) { got = c }}
	if err := a.reload(context.Background()); err == nil {
		t.Fatal("reload reported no error for a failed query")
	}
	if got.Err == nil {
		t.Fatal("OnReload was not told the read failed")
	}
	if got.Machines != 0 {
		t.Fatalf("Machines = %d, want 0 after a failed read", got.Machines)
	}
}

func TestCredentialUsedNamesWhatWasSent(t *testing.T) {
	withCap := reloadWithAdmin(t, capAd())
	if got := credentialUsed(withCap); !strings.Contains(got, "administrative capability") ||
		strings.Contains(got, "own credentials") {
		t.Fatalf("credentialUsed with a capability = %q", got)
	}
	without := reloadWithAdmin(t, noCapAd())
	if got := credentialUsed(without); !strings.Contains(got, "own credentials") {
		t.Fatalf("credentialUsed with no capability = %q", got)
	}
}

func reloadWithAdmin(t *testing.T, adText string) *startd.Admin {
	t.Helper()
	q := &fakeQuerier{ads: ads(t, adText)}
	a := &PoolActuator{Query: q}
	if err := a.reload(context.Background()); err != nil {
		t.Fatalf("reload: %v", err)
	}
	for _, admin := range a.admins {
		return admin
	}
	t.Fatal("reload produced no admin")
	return nil
}

// Every failure says which credentials it was sent with, not only the
// ones that arrive as a clean denial: an execute point that refuses at
// authentication closes the connection without a reply, so the usual
// shape of this failure is a read error.
func TestEveryFailureSaysWhichCredentialsItUsed(t *testing.T) {
	withCap := reloadWithAdmin(t, capAd())
	without := reloadWithAdmin(t, noCapAd())
	// The shape the pool actually fails in -- not a CAError, so a
	// check for a denial would miss it.
	eof := errors.New("reading the CA_UPDATE_MACHINE_AD reply: failed to read frame header: EOF")

	got := annotate(without, eof)
	if got == nil || !strings.Contains(got.Error(), "own credentials") {
		t.Fatalf("annotate without a capability = %v", got)
	}
	if !errors.Is(got, eof) {
		t.Fatal("annotate did not wrap the original error")
	}
	if got := annotate(withCap, eof); got == nil ||
		!strings.Contains(got.Error(), "administrative capability") {
		t.Fatalf("annotate with a capability = %v", got)
	}
	if annotate(without, nil) != nil {
		t.Fatal("annotate invented an error out of a success")
	}
	if got := annotate(nil, eof); !errors.Is(got, eof) {
		t.Fatalf("annotate with no admin = %v, want the error unchanged", got)
	}
}
