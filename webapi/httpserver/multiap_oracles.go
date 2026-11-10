package httpserver

import (
	"context"
	"sort"
	"strings"
	"sync"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
)

// maxOracleMembers bounds how many access points one refresh consults.
const maxOracleMembers = 64

// oracleMemberConcurrency bounds the consultations in flight.
const oracleMemberConcurrency = 8

// multiAPOracle runs a schedd-backed revocation oracle against every
// trusted member of the AP set and merges their answers.
//
// One grant is good at every AP, and each AP enforces its own decisions
// anyway: a user disabled on ap1 (condor_qusers -disable) is refused by
// ap1's schedd whatever the grant says. So the merged verdict only
// removes what no AP would allow any more:
//
//   - Revoked only when every member that answered says revoked. A user
//     disabled on one AP of fifty still has the other forty-nine.
//   - A scope is denied only when every member that answered denies it.
//   - No member answered: no opinion, as for one unreachable schedd.
//
// Asking only one member -- whichever happened to be first -- would make
// a user's grant depend on that AP's records alone, in both directions.
type multiAPOracle struct {
	name string
	// judgesUser is set for an oracle whose verdict is about the person
	// (user records), which each AP also enforces at route time
	// (admitToAP); an ACL oracle narrows scopes and is not consulted there.
	judgesUser bool
	members    func() []apregistry.Member
	perMember  func(apregistry.Member) RevocationOracle
}

// Name implements RevocationOracle.
func (o *multiAPOracle) Name() string { return o.name }

// Check implements RevocationOracle.
func (o *multiAPOracle) Check(ctx context.Context, username string, scopes []string) (ReauthDecision, error) {
	var targets []apregistry.Member
	for _, m := range o.members() {
		if m.Present && !m.Untrusted() && m.Schedd != nil {
			targets = append(targets, m)
		}
		if len(targets) == maxOracleMembers {
			break
		}
	}
	type answer struct {
		ap string
		d  ReauthDecision
	}
	var (
		mu      sync.Mutex
		answers []answer
		wg      sync.WaitGroup
		slots   = make(chan struct{}, oracleMemberConcurrency)
	)
	for _, m := range targets {
		wg.Add(1)
		go func(m apregistry.Member) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			d, err := o.perMember(m).Check(ctx, username, scopes)
			if err != nil || d.Status == UserStatusUnknown {
				// Fail open per member, as each oracle does on its own.
				return
			}
			mu.Lock()
			answers = append(answers, answer{ap: m.Name, d: d})
			mu.Unlock()
		}(m)
	}
	wg.Wait()
	sort.Slice(answers, func(i, j int) bool { return answers[i].ap < answers[j].ap })
	return mergeOracleAnswers(func(yield func(string, ReauthDecision)) {
		for _, a := range answers {
			yield(a.ap, a.d)
		}
	}), nil
}

// mergeOracleAnswers combines per-AP verdicts under multiAPOracle's
// rules. each yields (AP, decision) for every member that had an opinion.
func mergeOracleAnswers(each func(func(string, ReauthDecision))) ReauthDecision {
	n, revoked := 0, 0
	var reasons []string
	denied := map[string]int{}
	each(func(ap string, d ReauthDecision) {
		n++
		if d.Status == UserStatusRevoked {
			revoked++
			if d.Reason != "" {
				reasons = append(reasons, ap+": "+d.Reason)
			}
			return
		}
		seen := map[string]bool{}
		for _, sc := range d.DeniedScopes {
			if !seen[sc] {
				seen[sc] = true
				denied[sc]++
			}
		}
	})
	switch {
	case n == 0:
		return ReauthDecision{Status: UserStatusUnknown}
	case revoked == n:
		return ReauthDecision{Status: UserStatusRevoked, Reason: strings.Join(reasons, "; ")}
	}
	// Scopes every non-revoking member denied. A revoking member denies
	// everything, so it does not narrow the rest.
	active := n - revoked
	var out []string
	for sc, c := range denied {
		if c == active {
			out = append(out, sc)
		}
	}
	sort.Strings(out)
	d := ReauthDecision{Status: UserStatusActive, DeniedScopes: out}
	if len(out) > 0 {
		d.Reason = "no access point authorizes " + strings.Join(out, ", ")
	}
	return d
}

// multiAPOracles wraps each schedd-backed oracle to consult every member.
func (h *Handler) multiAPOracles(oracles []RevocationOracle) []RevocationOracle {
	if h.multi == nil {
		return oracles
	}
	members := h.multi.svc.Registry.Members
	out := make([]RevocationOracle, 0, len(oracles))
	for _, o := range oracles {
		switch base := o.(type) {
		case *UserRecordOracle:
			proto := *base
			out = append(out, &multiAPOracle{name: base.Name(), members: members, judgesUser: true,
				perMember: func(m apregistry.Member) RevocationOracle {
					one := proto
					one.Lookup = func() UserRecordLookup { return m.Schedd }
					return &one
				}})
		case *ScheddACLOracle:
			proto := *base
			out = append(out, &multiAPOracle{name: base.Name(), members: members,
				perMember: func(m apregistry.Member) RevocationOracle {
					one := proto
					sch := m.Schedd
					one.Schedd = func() *htcondor.Schedd { return sch }
					return &one
				}})
		default:
			out = append(out, o)
		}
	}
	return out
}
