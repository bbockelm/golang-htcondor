// Package aggregate renders the group keys of an htcondordb aggregate as this
// API spells them.
package aggregate

import (
	"github.com/PelicanPlatform/classad/db"
	"github.com/PelicanPlatform/classad/dbrpc"
)

// GroupLabel returns group column i of r as a label: a string group reads as
// its contents, and every other kind reads as its ClassAd text.
//
// htcondordb groups by the VALUE and identifies the group by that value's
// ClassAd text, so a string group arrives quoted -- "alice", not alice. That is
// what keeps the string "4" out of the integer 4's group, and the text stays
// the group's identity here too: this is only what a chart axis, an MCP answer
// or a JSON key says. Every reader of this API spells an owner alice, including
// the schedd-side aggregate that answers the same MCP tool when no mirror is
// reachable and builds its own groups from attribute values.
//
// A row from a server too old to send typed groups carries no values at all, so
// the label comes from parsing the text back. ParseGroupValue inverts every
// group text, and a text it cannot parse is returned unchanged rather than
// guessed at.
func GroupLabel(r dbrpc.AggRow, i int) string {
	if i < 0 || i >= len(r.Group) {
		return ""
	}
	v := db.ParseGroupValue(r.Group[i])
	if i < len(r.GroupValues) {
		v = r.GroupValues[i]
	}
	if v.IsString() {
		if s, err := v.StringValue(); err == nil {
			return s
		}
	}
	return r.Group[i]
}

// GroupLabels returns every group column of r as a label, in the row's order.
func GroupLabels(r dbrpc.AggRow) []string {
	if len(r.Group) == 0 {
		return nil
	}
	out := make([]string, len(r.Group))
	for i := range r.Group {
		out[i] = GroupLabel(r, i)
	}
	return out
}
