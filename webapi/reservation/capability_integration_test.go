//go:build integration

package reservation_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/reservation"
)

// The access point is the only party that knows whether a command rode
// the execute point's administrative capability or its own
// credentials: the refusal looks the same from the startd either way.
// These run against a real pool with remote administration on and off,
// and pin that the difference is visible without reading a startd log.

func capabilityHarness(t *testing.T, remoteAdmin string) (*reservation.PoolActuator, string) {
	t.Helper()
	cfg := "NUM_CPUS = 2\nMEMORY = 1024\n" +
		"SEC_ENABLE_REMOTE_ADMINISTRATION = " + remoteAdmin + "\n" +
		reservation.StartStanza + "\nUPDATE_INTERVAL = 3\n"
	_, coll := harness(t, cfg)
	machines := waitForSlots(t, coll)
	if len(machines) == 0 {
		t.Fatal("no machines advertised")
	}
	return &reservation.PoolActuator{Query: coll}, machines[0].Name
}

func TestCapabilitiesSeenOnAPoolThatPublishesThem(t *testing.T) {
	act, machine := capabilityHarness(t, "True")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if err := act.Probe(ctx, machine); err != nil {
		t.Fatalf("probing %s with remote administration on: %v", machine, err)
	}
	caps := act.Refreshed()
	if caps.Machines == 0 {
		t.Fatal("no execute points were read")
	}
	if caps.WithCapability != caps.Machines {
		t.Fatalf("%d of %d execute points published a capability, want all of them",
			caps.WithCapability, caps.Machines)
	}
	if caps.Degraded() {
		t.Fatal("a pool with remote administration on reports as degraded")
	}
}

// The ap2001 symptom: the push is refused and, before this was
// reported, nothing said the command had gone as the access point.
func TestCapabilitiesSeenOnAPoolThatDoesNot(t *testing.T) {
	act, machine := capabilityHarness(t, "False")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	err := act.Probe(ctx, machine)
	if err == nil {
		t.Fatal("the execute point accepted a machine-ad update with remote administration off")
	}
	if !strings.Contains(err.Error(), "own credentials") {
		t.Fatalf("the refusal does not say which credentials it used: %v", err)
	}

	caps := act.Refreshed()
	if caps.Machines == 0 {
		t.Fatal("no execute points were read")
	}
	if caps.WithCapability != 0 {
		t.Fatalf("WithCapability = %d, want 0 with remote administration off", caps.WithCapability)
	}
	if !caps.Degraded() {
		t.Fatal("a pool publishing no capabilities does not report as degraded")
	}
}
