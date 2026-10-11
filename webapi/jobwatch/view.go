package jobwatch

import (
	"encoding/json"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// AdView is a job ad rendered once into JSON values, keyed by the
// lower-cased attribute name, for handing the same state to several
// readers.
//
// A *classad.ClassAd cannot be shared that way. Its reads are not
// read-only: the first MarshalJSON or String of a freshly decoded ad
// sorts its attribute slice in place and clears a dirty flag, and
// evaluating an expression attribute records it in a per-ad map. Two
// goroutines serializing one ad race on the sort, and one of them can
// iterate the slice while the other reorders it. A fan-out therefore
// renders the ad once, on the goroutine that owns it, and hands out the
// result.
//
// An AdView is never modified after NewAdView returns, so any number of
// goroutines may read it, and the values in it, without synchronization.
// Readers must not modify it or the values it holds.
type AdView map[string]any

// NewAdView renders ad. The values are the shape the ad's own JSON
// marshalling produces -- what GET /api/v1/jobs/{id} returns -- so a
// client merging one into the job it already has sees no second encoding.
// Private attributes are left out, as they are from that marshalling.
//
// ad must not be in use by another goroutine. A nil ad gives a nil view;
// any other ad gives a non-nil one, empty if it does not render.
func NewAdView(ad *classad.ClassAd) AdView {
	if ad == nil {
		return nil
	}
	b, err := json.Marshal(ad)
	if err != nil {
		return AdView{}
	}
	var all map[string]any
	if err := json.Unmarshal(b, &all); err != nil {
		return AdView{}
	}
	// ClassAd attribute names are case-insensitive, and the JSON carries
	// whatever case the ad stored.
	v := make(AdView, len(all))
	for k, val := range all {
		v[strings.ToLower(k)] = val
	}
	return v
}

// Get returns the value of the attribute name, matched case-insensitively.
func (v AdView) Get(name string) (any, bool) {
	val, ok := v[strings.ToLower(name)]
	return val, ok
}

// Project picks attrs out of the view, keyed as the caller spelled them.
// Attributes the ad does not carry are omitted rather than recorded
// empty, so one appearing for the first time reads as a change.
//
// The returned map is the caller's own; the values in it are shared with
// the view and must not be modified.
func (v AdView) Project(attrs []string) map[string]any {
	out := make(map[string]any, len(attrs))
	for _, a := range attrs {
		if val, ok := v.Get(a); ok {
			out[a] = val
		}
	}
	return out
}
