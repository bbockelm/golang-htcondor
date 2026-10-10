package multiap

import (
	"time"
)

// APHubState is the hub's federation_sources view of one AP.
type APHubState struct {
	State            string `json:"state"`
	Reason           string `json:"reason,omitempty"`
	StalenessSeconds *int64 `json:"staleness_seconds,omitempty"`
	LastSeen         string `json:"last_seen,omitempty"`
	LastReset        string `json:"last_reset,omitempty"`
}

// APInfo is one AP as GET /api/v1/aps reports it.
type APInfo struct {
	Schedd string `json:"schedd"`
	// InCollector is whether the AP's schedd ad was in the last
	// collector poll. An AP that drops out stays listed.
	InCollector bool   `json:"in_collector"`
	Address     string `json:"address,omitempty"`
	FirstSeen   string `json:"first_seen,omitempty"`
	LastSeen    string `json:"last_seen,omitempty"`
	// Hub is the hub's state for the AP; state "absent" when the hub
	// does not hold it.
	Hub APHubState `json:"hub"`
	// Trust is whether the AP accepts this server's tokens, from the
	// registry's trust probe.
	Trust APTrust `json:"trust"`
}

// APTrust is the trust probe's view of one AP.
type APTrust struct {
	// State is "trusted", "untrusted" or "unknown" (not probed yet, or
	// the AP did not answer the probe).
	State     string `json:"state"`
	Reason    string `json:"reason,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
	// Actions is whether actions on the AP's jobs are attempted now:
	// false when it is untrusted or not advertised in the collector.
	Actions bool `json:"actions"`
}

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// APs lists the AP set with the registry's and the hub's view of each.
func (s *Service) APs() []APInfo {
	reachable := s.Hub.Status().Reachable
	members := s.Registry.Members()
	out := make([]APInfo, 0, len(members))
	for _, m := range members {
		info := APInfo{
			Schedd: m.Name, InCollector: m.Present, Address: m.Address,
			FirstSeen: rfc3339(m.FirstSeen), LastSeen: rfc3339(m.LastSeen),
		}
		state := m.Trust.State
		if state == "" {
			state = "unknown"
		}
		info.Trust = APTrust{State: state, Reason: m.Trust.Reason, CheckedAt: rfc3339(m.Trust.CheckedAt),
			Actions: m.Present && !m.Untrusted() && m.Schedd != nil}
		src, ok := s.Hub.Source(m.Name)
		switch {
		case ok:
			info.Hub = APHubState{State: src.State, Reason: src.Reason, LastSeen: rfc3339(src.LastSeen), LastReset: rfc3339(src.LastReset)}
			if src.StalenessKnown {
				st := src.Staleness
				info.Hub.StalenessSeconds = &st
			}
		case !reachable:
			info.Hub = APHubState{State: StateStale, Reason: "the federation hub is not answering"}
		default:
			info.Hub = APHubState{State: StateAbsent, Reason: "the federation hub does not hold this access point"}
		}
		out = append(out, info)
	}
	return out
}
