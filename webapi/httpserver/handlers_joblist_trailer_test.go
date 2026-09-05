package httpserver

import (
	"encoding/json"
	"strings"
	"testing"
)

// The web UI reads has_more to decide whether to tell the user their
// listing was cut short. Before it did, /jobs rendered the first 1000 of
// a 30,000-job queue as if that were the whole thing. These cases pin
// the contract that banner depends on.
func TestScheddJobListTrailer(t *testing.T) {
	cases := []struct {
		name     string
		jobCount int
		limit    int
		errorMsg string

		wantMore      bool
		wantReturned  float64
		wantErr       string
		wantNoCursor  bool // pagination_unavailable is present
		wantSourceKey string
	}{
		{
			name:          "under the limit is complete",
			jobCount:      42,
			limit:         1000,
			wantMore:      false,
			wantReturned:  42,
			wantSourceKey: "schedd",
		},
		{
			name:          "at the limit means more may match",
			jobCount:      1000,
			limit:         1000,
			wantMore:      true,
			wantReturned:  1000,
			wantNoCursor:  true,
			wantSourceKey: "schedd",
		},
		{
			// limit <= 0 is the "unlimited" sentinel: the answer is
			// whole by construction, however large.
			name:          "unlimited is never truncated",
			jobCount:      30456,
			limit:         -1,
			wantMore:      false,
			wantReturned:  30456,
			wantSourceKey: "schedd",
		},
		{
			// The listing stopped because it broke, not because it
			// filled up. Reporting has_more would send the caller after
			// rows that were never coming.
			name:          "an error suppresses has_more even at the limit",
			jobCount:      1000,
			limit:         1000,
			errorMsg:      "schedd went away",
			wantMore:      false,
			wantReturned:  1000,
			wantErr:       "schedd went away",
			wantSourceKey: "schedd",
		},
		{
			name:          "empty result",
			jobCount:      0,
			limit:         1000,
			wantMore:      false,
			wantReturned:  0,
			wantSourceKey: "schedd",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trailer := scheddJobListTrailer(tc.jobCount, tc.limit, tc.errorMsg)

			// The trailer closes an array the handler opened, so it
			// only parses in context.
			body := `{"jobs":[]` + strings.TrimPrefix(trailer, "]")

			var got map[string]any
			if err := json.Unmarshal([]byte(body), &got); err != nil {
				t.Fatalf("trailer does not close a valid document: %v\n%s", err, body)
			}

			if got["has_more"] != tc.wantMore {
				t.Errorf("has_more = %v, want %v", got["has_more"], tc.wantMore)
			}
			if got["total_returned"] != tc.wantReturned {
				t.Errorf("total_returned = %v, want %v", got["total_returned"], tc.wantReturned)
			}
			if got["source"] != tc.wantSourceKey {
				t.Errorf("source = %v, want %q", got["source"], tc.wantSourceKey)
			}

			gotErr, hasErr := got["error"]
			if tc.wantErr == "" && hasErr {
				t.Errorf("unexpected error field: %v", gotErr)
			}
			if tc.wantErr != "" && gotErr != tc.wantErr {
				t.Errorf("error = %v, want %q", gotErr, tc.wantErr)
			}

			_, hasNote := got["pagination_unavailable"]
			if hasNote != tc.wantNoCursor {
				t.Errorf("pagination_unavailable present = %v, want %v", hasNote, tc.wantNoCursor)
			}
			// When present it has to say something a user can act on --
			// the UI renders it verbatim.
			if hasNote {
				note, _ := got["pagination_unavailable"].(string)
				if !strings.Contains(note, "narrow") && !strings.Contains(note, "limit") {
					t.Errorf("the note gives the user nothing to do: %q", note)
				}
			}
		})
	}
}

// An error message with quotes or newlines must not break the document:
// it is interpolated into hand-built JSON.
func TestScheddJobListTrailerEscapesError(t *testing.T) {
	trailer := scheddJobListTrailer(3, 1000, `bad "thing" happened`+"\n<script>")
	var got map[string]any
	if err := json.Unmarshal([]byte(`{"jobs":[]`+strings.TrimPrefix(trailer, "]")), &got); err != nil {
		t.Fatalf("an error message broke the JSON: %v\n%s", err, trailer)
	}
	if got["error"] != `bad "thing" happened`+"\n<script>" {
		t.Errorf("error round-tripped as %q", got["error"])
	}
}
