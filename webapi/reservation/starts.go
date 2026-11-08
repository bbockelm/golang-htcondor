package reservation

import (
	"context"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// CollectorStarts reports each permissible execute point's published
// START, for the prober.
//
// Only, when not empty, is the site expression naming the execute points
// reservations may draw seats from, exactly as the census uses it.
type CollectorStarts struct {
	Query SlotQuerier
	Only  string
}

// startProjection is deliberately not SlotProjection: the prober needs
// only the machine name and the expression, and a pool-wide read every
// few minutes should carry as little as it can.
var startProjection = []string{"Machine", "Name", "START", "PartitionableSlot", "DynamicSlot"}

// Starts reads the published START of each candidate machine.
//
// The expression is taken unevaluated. A slot ad's START evaluates to
// true or false against the slot's own state, and composing against
// "false" would wedge the machine: it would admit nothing at all, for
// the life of the startd, with no way to take the attribute back.
func (c CollectorStarts) Starts(ctx context.Context) (map[string]string, error) {
	ads, _, err := c.Query.QueryAdsWithOptions(ctx, "StartdAd", censusConstraint(c.Only), &htcondor.QueryOptions{
		Limit:      slotLimit,
		Projection: startProjection,
	})
	if err != nil {
		return nil, err
	}
	return StartsFromAds(ads), nil
}

// usableStart rejects an expression there is no safe way to compose
// against.
//
// A string literal is the case worth guarding: `START = ""` is not a
// boolean, and `("") && (...)` evaluates to an error rather than a
// policy. The machine would then admit nothing at all for the life of
// the startd, and the attribute cannot be taken back. Leaving such a
// machine alone costs a seat; composing against it costs the machine.
func usableStart(text string) bool {
	if text == "" {
		return false
	}
	quoted := len(text) >= 2 && strings.HasPrefix(text, `"`) && strings.HasSuffix(text, `"`)
	return !quoted
}

// StartsFromAds collapses slot ads to one START per machine.
//
// A machine answers once. Its slots all share the ad the controller
// writes -- the startd merges pushed attributes into a single ad every
// slot publishes -- so provisioning is a per-machine act and reading one
// slot's START is reading the machine's.
//
// A dynamic slot is skipped when the machine also published a
// partitionable one: a d-slot's START can be narrowed by the job running
// on it, and the p-slot's is what governs admission.
func StartsFromAds(ads []*classad.ClassAd) map[string]string {
	out := map[string]string{}
	fromPartitionable := map[string]bool{}
	for _, ad := range ads {
		if ad == nil {
			continue
		}
		machine, ok := ad.EvaluateAttrString("Machine")
		if !ok || machine == "" {
			continue
		}
		expr, ok := ad.Lookup("START")
		if !ok || expr == nil {
			continue
		}
		text := strings.TrimSpace(expr.String())
		if !usableStart(text) {
			continue
		}
		part, _ := ad.EvaluateAttrBool("PartitionableSlot")
		if fromPartitionable[machine] && !part {
			continue
		}
		if part {
			fromPartitionable[machine] = true
		}
		out[machine] = text
	}
	return out
}
