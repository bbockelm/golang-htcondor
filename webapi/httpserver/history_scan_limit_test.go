package httpserver

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/bbockelm/golang-htcondor/webapi/internal/fakeschedd"
)

// /api/v1/jobs/archive reports a schedd scan that stopped at its scan limit,
// buffered and streamed, so an empty page is not mistaken for "no such jobs".
func TestJobArchiveReportsScanLimitCutoff(t *testing.T) {
	f := twoOwnerScheddServer(t)
	// Twenty newer records on top of the fixture's 11.0 (alice) and 12.0.
	for c := 100; c < 120; c++ {
		f.schedd.AddHistory(fakeschedd.JobAd(c, 0, "alice", 4))
	}

	for _, stream := range []string{"false", "true"} {
		t.Run("stream_results="+stream, func(t *testing.T) {
			q := url.Values{
				"constraint":     {"ClusterId == 11"},
				"scan_limit":     {"5"},
				"limit":          {"3"},
				"stream_results": {stream},
			}
			w := f.do(t, http.MethodGet, "/api/v1/jobs/archive?"+q.Encode(), "", f.session(t, "alice"))
			if w.Code != http.StatusOK {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			var resp struct {
				Ads              []map[string]interface{} `json:"ads"`
				ScanLimitReached bool                     `json:"scan_limit_reached"`
				RecordsScanned   int                      `json:"records_scanned"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decoding %s: %v", w.Body.String(), err)
			}
			if len(resp.Ads) != 0 || !resp.ScanLimitReached || resp.RecordsScanned != 5 {
				t.Errorf("got %d ads, scan_limit_reached=%v, records_scanned=%d; want 0, true, 5 (%s)",
					len(resp.Ads), resp.ScanLimitReached, resp.RecordsScanned, w.Body.String())
			}

			// Searching far enough back finds the record and reports no cut-off.
			q.Set("scan_limit", "100")
			w = f.do(t, http.MethodGet, "/api/v1/jobs/archive?"+q.Encode(), "", f.session(t, "alice"))
			resp.Ads, resp.ScanLimitReached, resp.RecordsScanned = nil, false, 0
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decoding %s: %v", w.Body.String(), err)
			}
			if len(resp.Ads) != 1 || resp.ScanLimitReached {
				t.Errorf("got %d ads, scan_limit_reached=%v; want 1 and no cut-off (%s)",
					len(resp.Ads), resp.ScanLimitReached, w.Body.String())
			}
		})
	}
}
