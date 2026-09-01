package mcpserver

import (
	"strings"
	"testing"
)

// TestClampToolLimitCeiling: these tools answer into a model's context,
// so "unlimited" is exactly the answer that does not fit. Both an
// explicit request for everything and a request past the ceiling come
// back at the ceiling, flagged so the caller can be told that raising
// the limit is not the way forward.
func TestClampToolLimitCeiling(t *testing.T) {
	cases := map[string]struct {
		requested  int
		wantLimit  int
		wantCapped bool
	}{
		"a modest request is honored":    {requested: 50, wantLimit: 50, wantCapped: false},
		"exactly the ceiling is honored": {requested: maxToolResults, wantLimit: maxToolResults, wantCapped: false},
		"past the ceiling is capped":     {requested: 10000, wantLimit: maxToolResults, wantCapped: true},
		"unlimited (-1) is capped":       {requested: -1, wantLimit: maxToolResults, wantCapped: true},
		"unset (0) is capped":            {requested: 0, wantLimit: maxToolResults, wantCapped: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			limit, capped := clampToolLimit(c.requested)
			if limit != c.wantLimit || capped != c.wantCapped {
				t.Errorf("clampToolLimit(%d) = (%d, %v), want (%d, %v)",
					c.requested, limit, capped, c.wantLimit, c.wantCapped)
			}
		})
	}
}

// TestTruncationNoteAdvisesWhatWillHelp: the two truncation cases need
// opposite advice, and giving the wrong one sends the caller in a
// circle. A caller who set a small limit can raise it; a caller who hit
// the ceiling cannot, and has to narrow the query or ask for a count.
func TestTruncationNoteAdvisesWhatWillHelp(t *testing.T) {
	capped := truncationNote(maxToolResults, maxToolResults, true)
	if !strings.Contains(capped, "not return more") {
		t.Errorf("a capped answer must say raising the limit will not help:\n%s", capped)
	}
	if !strings.Contains(capped, "aggregate_jobs") {
		t.Errorf("a capped answer must name the tool that can answer instead:\n%s", capped)
	}

	own := truncationNote(50, 50, false)
	if !strings.Contains(own, "Raise limit") {
		t.Errorf("a self-limited answer should say the limit can be raised:\n%s", own)
	}
	// ...but not past the ceiling, or the next call is capped and the
	// caller has learned nothing.
	if !strings.Contains(own, "500") {
		t.Errorf("a self-limited answer should name the ceiling it can be raised to:\n%s", own)
	}
}
