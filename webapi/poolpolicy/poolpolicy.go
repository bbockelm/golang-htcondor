// Package poolpolicy decides which collector attributes a caller may read.
//
// Slot and submitter ads describe other people: a busy slot names the user
// running on it, their project, the access point they submitted from and
// how their job is behaving. That is what condor_status tells any user, so
// it is not a defect; what changed is that an agent can pull all of it in
// one call, from anywhere the API is reachable.
//
// The restriction is an ALLOWLIST rather than a list of attributes to
// strip. A denylist cannot be made complete: a site is free to advertise
// anything it likes from its STARTD_ATTRS, so naming the attributes that
// carry personal data means guessing at every site's custom ones. An
// allowlist is wrong in the safe direction -- a site whose own attribute
// is missing sees it absent and can add it by configuration, rather than
// having it published and finding out later.
//
// Submitter ads are refused outright rather than filtered. Their Name IS
// the user, one ad per person with jobs in the pool, so there is no
// redacted form of a submitter ad that still answers anything.
package poolpolicy

import (
	"fmt"
	"sort"
	"strings"
)

// Mode is what HTTP_API_POOL_QUERY_IDENTITY selects.
type Mode int

const (
	// ModeOpen places no restriction: every caller reads what
	// condor_status would show them. The default, so that upgrading
	// does not change what an existing deployment answers.
	ModeOpen Mode = iota
	// ModeRestricted confines callers without the cross-user read
	// privilege to the allowlist, and refuses them submitter ads.
	ModeRestricted
	// ModeAdmin requires the cross-user read privilege for any pool
	// query at all.
	ModeAdmin
)

func (m Mode) String() string {
	switch m {
	case ModeRestricted:
		return "restricted"
	case ModeAdmin:
		return "admin"
	default:
		return "open"
	}
}

// ParseMode reads the configured value. An unrecognised value is an error
// rather than a silent fallback: this setting exists to withhold data, and
// a typo that quietly left it open would be the one failure that matters.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "open":
		return ModeOpen, nil
	case "restricted":
		return ModeRestricted, nil
	case "admin":
		return ModeAdmin, nil
	default:
		return ModeOpen, fmt.Errorf("unknown value %q: use open, restricted or admin", s)
	}
}

// Attribute names are compared case-insensitively, as ClassAd attribute
// names are, so every set here is keyed by the lowercased name.
func fold(names []string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			m[strings.ToLower(n)] = true
		}
	}
	return m
}

// slotAllowed is the default allowlist for slot (startd) ads: what the
// machine is, what it has, and whether it is busy -- never who is on it.
//
// It is the union of what this server's own pages already read: the pool
// page's projection, query_pool's listing default, and the chat
// assistant's slot tool, each minus their identity attributes. Keeping it
// a superset of those is what lets the UI keep working unchanged; the
// test asserts that, so a page that grows a column cannot silently start
// coming back empty.
var slotAllowed = fold([]string{
	// Which machine, and what kind of slot.
	"Name", "Machine", "SlotType", "SlotID", "PartitionableSlot", "DynamicSlot",
	"BackfillSlot", "NumDynamicSlots",
	// Busy or not. State and Activity say that without naming anyone.
	"State", "Activity", "EnteredCurrentState", "EnteredCurrentActivity",
	// What it has, and what is left.
	"Cpus", "Memory", "Disk", "GPUs", "LoadAvg",
	"TotalCpus", "TotalMemory", "TotalDisk", "TotalGPUs", "TotalSlotGPUs",
	"TotalSlotCpus", "TotalSlotMemory", "TotalSlotDisk",
	// What kind of machine.
	"OpSys", "OpSysAndVer", "OpSysMajorVer", "Arch", "CondorVersion",
	// Which GPU model, which is a property of the hardware. AssignedGPUs
	// names the device a job holds, not the job or its owner.
	"AssignedGPUs", "GPUs_DeviceName", "CUDADeviceName", "CUDACapability",
	"CUDAGlobalMemoryMb", "CUDADriverVersion",
})

// aggregateAllowed is the allowlist for the ad types that describe daemons
// rather than people: schedd, negotiator and collector ads. Their counts
// are per access point or per pool, not per user.
var aggregateAllowed = fold([]string{
	"Name", "Machine", "CondorVersion", "MyType",
	"TotalRunningJobs", "TotalIdleJobs", "TotalHeldJobs", "TotalJobAds",
	"TotalRemovedJobs", "TotalSchedulerJobsRunning", "TotalLocalJobsRunning",
	"NumUsers", "MaxJobsRunning", "RecentDaemonCoreDutyCycle",
	"HostsTotal", "HostsClaimed", "HostsUnclaimed", "HostsOwner",
	"RunningJobs", "IdleJobs", "SubmitterAds",
	"LastNegotiationCycleEnd0", "LastNegotiationCycleDuration0",
	"LastNegotiationCycleMatches0", "LastNegotiationCycleRejections0",
	"LastNegotiationCycleNumSchedulers0", "LastNegotiationCycleTotalSlots0",
})

// Policy is the configured restriction, ready to apply.
type Policy struct {
	Mode Mode
	// extra is HTTP_API_POOL_QUERY_EXTRA_ATTRS: attributes a site has
	// decided are safe to publish, added to every ad type's allowlist.
	extra map[string]bool
}

// New builds a Policy. extraAttrs is the site's additions, already split.
func New(mode Mode, extraAttrs []string) *Policy {
	return &Policy{Mode: mode, extra: fold(extraAttrs)}
}

// Restricts reports whether this caller is held to the allowlist.
// privileged is the caller's cross-user read privilege, which the caller's
// own package determines -- this package does not know how that is granted.
func (p *Policy) Restricts(privileged bool) bool {
	return p != nil && p.Mode == ModeRestricted && !privileged
}

// Refuses reports whether this caller may not query the pool at all.
func (p *Policy) Refuses(privileged bool) bool {
	return p != nil && p.Mode == ModeAdmin && !privileged
}

// allowed returns the attribute set for one ad type, site additions
// included. adType is the collector's spelling ("StartdAd", "ScheddAd").
func (p *Policy) allowed(adType string) map[string]bool {
	base := aggregateAllowed
	if strings.EqualFold(adType, "StartdAd") || strings.EqualFold(adType, "Machine") {
		base = slotAllowed
	}
	if len(p.extra) == 0 {
		return base
	}
	merged := make(map[string]bool, len(base)+len(p.extra))
	for k := range base {
		merged[k] = true
	}
	for k := range p.extra {
		merged[k] = true
	}
	return merged
}

// AllowedAttrs lists the attributes a restricted caller may read of this ad
// type, sorted. It is what a projection is clamped to when the caller asked
// for everything.
func (p *Policy) AllowedAttrs(adType string) []string {
	set := p.allowed(adType)
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SubmitterAdType is the ad type a restricted caller may not read at all.
const SubmitterAdType = "SubmitterAd"

// ErrSubmitterRestricted explains the one ad type that has no redacted form.
type ErrSubmitterRestricted struct{}

func (ErrSubmitterRestricted) Error() string {
	return "submitter ads are not available at this site: every submitter ad names one user, " +
		"so there is no form of it that does not identify them. Ask what the pool has (ad_type 'slots') " +
		"or what the access points report (ad_type 'schedd') instead"
}

// CheckAdType refuses the ad types a restricted caller may not read.
func (p *Policy) CheckAdType(privileged bool, adType string) error {
	if !p.Restricts(privileged) {
		return nil
	}
	if strings.EqualFold(adType, SubmitterAdType) || strings.EqualFold(adType, "Submitter") {
		return ErrSubmitterRestricted{}
	}
	return nil
}
