package poolpolicy

import (
	"strings"
	"testing"
)

func TestParseMode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Mode
		bad  bool
	}{
		{"", ModeOpen, false},
		{"open", ModeOpen, false},
		{"RESTRICTED", ModeRestricted, false},
		{" admin ", ModeAdmin, false},
		{"yes", ModeOpen, true},
		{"true", ModeOpen, true},
	} {
		got, err := ParseMode(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("ParseMode(%q): want error, got %v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseMode(%q): %v", tc.in, err)
		} else if got != tc.want {
			t.Errorf("ParseMode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// A typo must not quietly leave the pool open; that is the one failure of
// this setting that would matter.
func TestParseModeRejectsBooleanSpelling(t *testing.T) {
	if _, err := ParseMode("1"); err == nil {
		t.Fatal(`ParseMode("1"): want an error, got none`)
	}
}

func TestRestrictsAndRefuses(t *testing.T) {
	for _, tc := range []struct {
		mode               Mode
		priv               bool
		restricts, refuses bool
	}{
		{ModeOpen, false, false, false},
		{ModeOpen, true, false, false},
		{ModeRestricted, false, true, false},
		{ModeRestricted, true, false, false},
		{ModeAdmin, false, false, true},
		{ModeAdmin, true, false, false},
	} {
		p := New(tc.mode, nil)
		if got := p.Restricts(tc.priv); got != tc.restricts {
			t.Errorf("%v priv=%v: Restricts = %v, want %v", tc.mode, tc.priv, got, tc.restricts)
		}
		if got := p.Refuses(tc.priv); got != tc.refuses {
			t.Errorf("%v priv=%v: Refuses = %v, want %v", tc.mode, tc.priv, got, tc.refuses)
		}
	}
}

func TestProjectionRefusesIdentityAndStar(t *testing.T) {
	p := New(ModeRestricted, nil)
	if err := p.CheckProjection(false, "StartdAd", []string{"Name", "State", "Cpus"}); err != nil {
		t.Fatalf("safe projection refused: %v", err)
	}
	for _, bad := range []string{"RemoteOwner", "remoteowner", "RemoteUser", "RemoteProject",
		"ConcurrencyLimits", "ClientMachine", "GlobalJobId", "JobPid", "*"} {
		if err := p.CheckProjection(false, "StartdAd", []string{"Name", bad}); err == nil {
			t.Errorf("projection %q was allowed", bad)
		}
	}
	// A privileged caller is unaffected.
	if err := p.CheckProjection(true, "StartdAd", []string{"*"}); err != nil {
		t.Errorf("privileged caller refused: %v", err)
	}
}

func TestConstraintIsCheckedNotJustOutput(t *testing.T) {
	p := New(ModeRestricted, nil)
	ok := []string{
		`State == "Claimed"`,
		`GPUs > 0 && Memory > 4096`,
		`!(State == "Owner") || Activity =?= "Idle"`,
		`regexp("node0.*", Machine)`,
		`(Cpus ?: 0) > 2`,
		`State == "Claimed" ? Cpus > 1 : false`,
		`member(Arch, {"X86_64"})`,
	}
	for _, c := range ok {
		if err := p.CheckConstraint(false, "StartdAd", c); err != nil {
			t.Errorf("constraint %q refused: %v", c, err)
		}
	}
	// The whole point: an attribute never returned is still an oracle.
	bad := []string{
		`RemoteOwner == "alice@wisc.edu"`,
		`State == "Claimed" && RemoteOwner =!= undefined`,
		`regexp("alice", RemoteUser)`,
		`(RemoteProject ?: "x") == "chem"`,
		`true ? RemoteOwner =!= undefined : false`,
		`member("x", ConcurrencyLimits)`,
		`eval("RemoteOwner")`,
	}
	for _, c := range bad {
		if err := p.CheckConstraint(false, "StartdAd", c); err == nil {
			t.Errorf("constraint %q was allowed", c)
		}
	}
}

// An unrecognised node type must refuse the constraint, not walk past the
// subtree that contains it.
func TestConstraintFailsClosed(t *testing.T) {
	p := New(ModeRestricted, nil)
	for _, c := range []string{`[a = RemoteOwner]`, `{1,2}[0] == RemoteOwner`} {
		if err := p.CheckConstraint(false, "StartdAd", c); err == nil {
			t.Errorf("constraint %q was allowed", c)
		}
	}
	if err := p.CheckConstraint(false, "StartdAd", `State ==`); err == nil {
		t.Error("unparseable constraint was allowed")
	}
}

func TestSubmitterAdsRefusedWhenRestricted(t *testing.T) {
	p := New(ModeRestricted, nil)
	if err := p.CheckAdType(false, "SubmitterAd"); err == nil {
		t.Error("submitter ads allowed to a restricted caller")
	}
	if err := p.CheckAdType(true, "SubmitterAd"); err != nil {
		t.Errorf("submitter ads refused to a privileged caller: %v", err)
	}
	if err := New(ModeOpen, nil).CheckAdType(false, "SubmitterAd"); err != nil {
		t.Errorf("submitter ads refused while open: %v", err)
	}
	if err := p.CheckAdType(false, "StartdAd"); err != nil {
		t.Errorf("slot ads refused: %v", err)
	}
}

func TestFilterAdDropsIdentity(t *testing.T) {
	p := New(ModeRestricted, nil)
	in := map[string]interface{}{
		"Name": "slot1@node01", "State": "Claimed",
		"RemoteOwner": "alice@wisc.edu", "SiteSecretAttr": "x",
	}
	out := p.FilterAd(false, "StartdAd", in)
	if _, ok := out["RemoteOwner"]; ok {
		t.Error("RemoteOwner survived the filter")
	}
	// An attribute nobody listed is dropped too: that is the allowlist
	// working, and is why a site adds its own by configuration.
	if _, ok := out["SiteSecretAttr"]; ok {
		t.Error("an unlisted custom attribute survived the filter")
	}
	if out["Name"] != "slot1@node01" || out["State"] != "Claimed" {
		t.Errorf("safe attributes were dropped: %v", out)
	}
	if got := p.FilterAd(true, "StartdAd", in); len(got) != len(in) {
		t.Error("a privileged caller's ad was filtered")
	}
}

func TestExtraAttrsAreHonoured(t *testing.T) {
	p := New(ModeRestricted, []string{"GLIDEIN_Site", " CUSTOM_Thing "})
	if err := p.CheckProjection(false, "StartdAd", []string{"GLIDEIN_Site", "CUSTOM_Thing"}); err != nil {
		t.Errorf("site-added attributes refused: %v", err)
	}
	if err := p.CheckConstraint(false, "StartdAd", `GLIDEIN_Site == "x"`); err != nil {
		t.Errorf("site-added attribute refused in a constraint: %v", err)
	}
	if err := p.CheckProjection(false, "StartdAd", []string{"RemoteOwner"}); err == nil {
		t.Error("extra attributes widened the list to identity")
	}
}

func TestClampProjectionFillsTheDefault(t *testing.T) {
	p := New(ModeRestricted, nil)
	got := p.ClampProjection(false, "StartdAd", nil)
	if len(got) == 0 {
		t.Fatal("an empty projection was left empty, which means the ad's full contents")
	}
	for _, a := range got {
		if strings.EqualFold(a, "RemoteOwner") {
			t.Error("the clamped default includes RemoteOwner")
		}
	}
	if got := p.ClampProjection(true, "StartdAd", nil); got != nil {
		t.Error("a privileged caller's empty projection was clamped")
	}
}

// The allowlist has to stay a superset of what this server's own pages
// read, or a restricted site's pool page comes back empty. These are the
// projections those pages use, minus the identity attributes they lose.
func TestAllowlistCoversWhatThePagesRead(t *testing.T) {
	p := New(ModeRestricted, nil)
	// webapi/httpserver/pool_summary.go poolSlotProjection, less RemoteOwner.
	poolSummary := []string{
		"Name", "Machine", "SlotType", "PartitionableSlot", "DynamicSlot", "BackfillSlot",
		"Cpus", "Memory", "GPUs", "TotalCpus", "TotalMemory", "TotalGPUs", "TotalSlotGPUs",
		"NumDynamicSlots", "State", "Activity",
	}
	// webapi/mcpserver/handlers_pool.go, the slots kind's listAttrs.
	queryPool := []string{
		"Name", "Machine", "SlotType", "State", "Activity",
		"Cpus", "Memory", "Disk", "GPUs", "LoadAvg",
		"OpSys", "OpSysAndVer", "Arch", "EnteredCurrentState",
	}
	// webapi/httpserver/handlers_chat_slots_tool.go.
	chatSlots := []string{
		"Name", "Machine", "SlotType", "PartitionableSlot", "DynamicSlot",
		"Cpus", "Memory", "Disk", "TotalCpus", "TotalMemory", "TotalDisk", "TotalGpus",
		"OpSys", "OpSysAndVer", "Arch", "State", "Activity",
		"GPUs", "AssignedGPUs", "TotalSlotGPUs",
		"GPUs_DeviceName", "CUDADeviceName", "CUDACapability", "CUDAGlobalMemoryMb", "CUDADriverVersion",
	}
	// webapi/frontend/src/lib/pool.ts SLOT_PROJECTION, less RemoteOwner.
	uiPool := []string{
		"Name", "Machine", "SlotType", "PartitionableSlot", "DynamicSlot", "BackfillSlot",
		"Cpus", "Memory", "Disk", "GPUs", "TotalCpus", "TotalMemory", "TotalGPUs",
		"TotalSlotGPUs", "NumDynamicSlots", "State", "Activity", "AssignedGPUs",
		"Arch", "OpSys", "OpSysAndVer",
	}
	for name, set := range map[string][]string{
		"pool_summary.go": poolSummary, "query_pool": queryPool,
		"chat slots tool": chatSlots, "pool.ts SLOT_PROJECTION": uiPool,
	} {
		if err := p.CheckProjection(false, "StartdAd", set); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestScheddAdsUseTheAggregateList(t *testing.T) {
	p := New(ModeRestricted, nil)
	if err := p.CheckProjection(false, "ScheddAd",
		[]string{"Name", "Machine", "TotalRunningJobs", "TotalIdleJobs", "NumUsers"}); err != nil {
		t.Errorf("schedd projection refused: %v", err)
	}
	// A schedd ad is not a slot ad; slot resource attributes are not in
	// its list, and neither is anything naming a user.
	if err := p.CheckProjection(false, "ScheddAd", []string{"RemoteOwner"}); err == nil {
		t.Error("RemoteOwner allowed on a schedd ad")
	}
}
