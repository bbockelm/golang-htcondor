//go:build integration

// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package startd_test

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/startd"
)

// Administering an execute point through the capability it publishes
// rests on four claims about HTCondor that are cheap to assert against
// a ClassAd this package wrote and expensive to get wrong in a pool:
//
//   - the startd publishes an administrative capability, and the
//     collector hides it unless the query asks for private attributes;
//   - the capability imports as a security session and authorizes
//     CA_AUTH_CMD even when the execute point's own ALLOW_WRITE and
//     ALLOW_ADMINISTRATOR name somebody else;
//   - an attribute pushed with CA_UPDATE_MACHINE_AD reaches every slot
//     ad the machine publishes, not just one;
//   - the startd merges the protocol's own Command attribute along with
//     it, because its filter does not exclude it.
//
// The last is a wart rather than a feature, and it is asserted because
// the design that uses this mechanism had to be written around it.

func harness(t *testing.T, extra string) (*htcondor.CondorTestHarness, *htcondor.Collector) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	if _, err := exec.LookPath("condor_master"); err != nil {
		t.Skip("condor_master not in PATH")
	}
	h := htcondor.SetupCondorHarnessWithConfig(t, extra)
	if err := h.WaitForDaemons(); err != nil {
		t.Fatalf("daemons failed to start: %v", err)
	}
	return h, htcondor.NewCollector(h.GetCollectorAddr())
}

// slotAds polls the collector until the startd has advertised.
func slotAds(t *testing.T, coll *htcondor.Collector, private bool) []*classad.ClassAd {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		ads, _, err := coll.QueryAdsWithOptions(context.Background(), "StartdAd", "", &htcondor.QueryOptions{
			Limit:             100,
			Projection:        []string{"*"},
			PrivateAttributes: private,
		})
		if err == nil && len(ads) > 0 {
			return ads
		}
		if time.Now().After(deadline) {
			t.Fatalf("no slots advertised within the deadline (last error: %v)", err)
		}
		time.Sleep(time.Second)
	}
}

// TestCapabilityIsAPrivateAttribute: the collector moves the capability
// into the private ad, so an ordinary query cannot see it. If it could,
// anybody who may run condor_status could administer every execute
// point in the pool.
func TestCapabilityIsAPrivateAttribute(t *testing.T) {
	_, coll := harness(t, "SEC_ENABLE_REMOTE_ADMINISTRATION = True\n")

	withPrivate := slotAds(t, coll, true)
	var found string
	for _, ad := range withPrivate {
		if v, ok := ad.EvaluateAttrString(startd.AdminCapabilityAttr); ok && v != "" {
			found = v
			break
		}
	}
	if found == "" {
		t.Fatalf("no slot ad carried %s even with private attributes asked for", startd.AdminCapabilityAttr)
	}

	withoutPrivate := slotAds(t, coll, false)
	for _, ad := range withoutPrivate {
		if v, ok := ad.EvaluateAttrString(startd.AdminCapabilityAttr); ok && v != "" {
			t.Errorf("an ordinary query returned the administrative capability")
			break
		}
	}
}

// TestUpdateMachineAdThroughTheCapability is the load-bearing one. The
// execute point's own authorization lists name an identity this test
// does not have, so a direct connection is refused; the capability
// DaemonCore minted for itself is the only thing that can authorize the
// push. It then has to show up on every slot of that machine.
func TestUpdateMachineAdThroughTheCapability(t *testing.T) {
	// The startd refuses this process directly. DaemonCore punches its
	// own ADMINISTRATOR hole for collector-side@matchsession when remote
	// administration is on, independently of these lists, so the
	// capability path is unaffected.
	const cfg = `
SEC_ENABLE_REMOTE_ADMINISTRATION = True
NUM_CPUS = 4
STARTD.ALLOW_WRITE = nobody@nowhere.invalid
STARTD.ALLOW_ADMINISTRATOR = nobody@nowhere.invalid
`
	_, coll := harness(t, cfg)

	ads := slotAds(t, coll, true)
	var withCap *classad.ClassAd
	for _, ad := range ads {
		if v, ok := ad.EvaluateAttrString(startd.AdminCapabilityAttr); ok && v != "" {
			withCap = ad
			break
		}
	}
	if withCap == nil {
		t.Fatalf("no slot ad carried an administrative capability")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Without the capability, this process cannot administer the startd.
	direct := startd.NewAdmin(mustAddr(t, withCap), nil)
	refused := classad.New()
	_ = refused.Set("StartdAdminE2EDirect", int64(1))
	if err := direct.UpdateMachineAd(ctx, refused); err == nil {
		t.Errorf("a direct push succeeded although the startd authorizes nobody@nowhere.invalid")
	}

	// With it, the same push is authorized.
	admin, err := startd.NewAdminFromAd(withCap, true, nil)
	if err != nil {
		t.Fatalf("NewAdminFromAd: %v", err)
	}
	if !admin.HasCapability() {
		t.Fatalf("Admin did not import the capability")
	}

	update := classad.New()
	_ = update.Set("StartdAdminE2EMarker", int64(4242))
	if err := admin.UpdateMachineAd(ctx, update); err != nil {
		t.Fatalf("UpdateMachineAd through the capability: %v", err)
	}

	machine, _ := withCap.EvaluateAttrString("Machine")
	deadline := time.Now().Add(90 * time.Second)
	for {
		fresh := slotAds(t, coll, false)
		var slots, carried, withCommand int
		for _, ad := range fresh {
			if m, _ := ad.EvaluateAttrString("Machine"); m != machine {
				continue
			}
			slots++
			if v, ok := ad.EvaluateAttrInt("StartdAdminE2EMarker"); ok && v == 4242 {
				carried++
			}
			if v, ok := ad.EvaluateAttrString("Command"); ok && v == startd.VerbUpdateMachineAd {
				withCommand++
			}
		}
		if slots > 0 && carried == slots {
			// The merge is per machine: every slot carries it, which is
			// why holding has to be a per-machine act.
			if withCommand != slots {
				t.Errorf("Command reached %d of %d slot ads; the startd's filter does not exclude it, so it should reach all", withCommand, slots)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the pushed attribute reached %d of %d slot ads on %s", carried, slots, machine)
		}
		time.Sleep(2 * time.Second)
	}
}

// TestPushedAttributeIsAnEvaluationOperand: the attribute has to be
// merged into the ad the slot evaluates its own expressions against,
// not merely into what the collector shows. Everything built on this
// mechanism depends on a pushed attribute being readable by START.
//
// The startd is configured to publish an attribute computed from one
// this test pushes. If the push were only decorating the outgoing ad,
// the computed attribute would never change.
func TestPushedAttributeIsAnEvaluationOperand(t *testing.T) {
	const cfg = `
SEC_ENABLE_REMOTE_ADMINISTRATION = True
StartdAdminEcho = ( StartdAdminE2EOperand ?: -1 )
STARTD_ATTRS = $(STARTD_ATTRS) StartdAdminEcho
`
	_, coll := harness(t, cfg)

	ads := slotAds(t, coll, true)
	var withCap *classad.ClassAd
	for _, ad := range ads {
		if v, ok := ad.EvaluateAttrString(startd.AdminCapabilityAttr); ok && v != "" {
			withCap = ad
			break
		}
	}
	if withCap == nil {
		t.Fatalf("no slot ad carried an administrative capability")
	}
	if v, ok := withCap.EvaluateAttrInt("StartdAdminEcho"); !ok || v != -1 {
		t.Fatalf("StartdAdminEcho = %v (present=%v) before the push, want -1", v, ok)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	admin, err := startd.NewAdminFromAd(withCap, true, nil)
	if err != nil {
		t.Fatalf("NewAdminFromAd: %v", err)
	}
	update := classad.New()
	_ = update.Set("StartdAdminE2EOperand", int64(7))
	if err := admin.UpdateMachineAd(ctx, update); err != nil {
		t.Fatalf("UpdateMachineAd: %v", err)
	}

	machine, _ := withCap.EvaluateAttrString("Machine")
	deadline := time.Now().Add(90 * time.Second)
	for {
		for _, ad := range slotAds(t, coll, false) {
			if m, _ := ad.EvaluateAttrString("Machine"); m != machine {
				continue
			}
			if v, ok := ad.EvaluateAttrInt("StartdAdminEcho"); ok && v == 7 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("StartdAdminEcho never saw the pushed operand; a pushed attribute is not reaching the slot's own evaluation")
		}
		time.Sleep(2 * time.Second)
	}
}

func mustAddr(t *testing.T, ad *classad.ClassAd) string {
	t.Helper()
	addr, ok := ad.EvaluateAttrString("MyAddress")
	if !ok || addr == "" {
		t.Fatalf("slot ad carries no MyAddress")
	}
	return addr
}
