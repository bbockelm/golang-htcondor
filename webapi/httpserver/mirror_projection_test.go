package httpserver

import "testing"

// TestNormalizeMirrorProjection guards the archive-detail regression: the
// frontend asks the mirror for projection=* ("all attributes"), but the mirror
// reads an EMPTY projection as "all" and a literal "*" as an attribute name no
// ad has. Left untranslated, /archive/<id> streamed ads stripped to their type
// fields and rendered nothing. A wildcard must collapse to the empty projection.
func TestNormalizeMirrorProjection(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"bare wildcard means all -> empty", []string{"*"}, nil},
		{"wildcard anywhere means all -> empty", []string{"Owner", "*", "JobStatus"}, nil},
		{"named projection is preserved", []string{"Owner", "JobStatus"}, []string{"Owner", "JobStatus"}},
		{"empty stays empty (already means all)", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeMirrorProjection(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("normalizeMirrorProjection(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("normalizeMirrorProjection(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}
