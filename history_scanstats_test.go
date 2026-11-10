package htcondor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	cedarserver "github.com/bbockelm/cedar/server"
)

// fakeHistoryDaemon answers QUERY_SCHEDD_HISTORY the way condor_history does
// in its writetosocket mode: it walks its records newest first, counting each
// one it examines, sends the matches, and stops at whichever comes first --
// NumJobMatches matches or ScanLimit records examined. The closing ad carries
// Owner = 0, NumMatches, MalformedAds and AdCount.
type fakeHistoryDaemon struct {
	addr string
	// records are newest first, the order a backwards scan visits them.
	records []*classad.ClassAd
	// omitAdCount leaves AdCount out of the closing ad, as a daemon that
	// predates it would.
	omitAdCount bool

	mu      sync.Mutex
	request *classad.ClassAd
}

func newFakeHistoryDaemon(t *testing.T, records []*classad.ClassAd, omitAdCount bool) *fakeHistoryDaemon {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0") //nolint:noctx // test-only loopback listener
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeHistoryDaemon{addr: fmt.Sprintf("<%s>", ln.Addr().String()), records: records, omitAdCount: omitAdCount}

	srv := cedarserver.New(&security.SecurityConfig{
		AuthMethods:    []security.AuthMethod{security.AuthFS},
		Authentication: security.SecurityRequired,
		CryptoMethods:  []security.CryptoMethod{security.CryptoAES},
		Encryption:     security.SecurityRequired,
		Integrity:      security.SecurityRequired,
		SessionCache:   security.NewSessionCache(),
	})
	srv.Handle(commands.QUERY_SCHEDD_HISTORY, f.serve, "READ")

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	return f
}

func (f *fakeHistoryDaemon) serve(ctx context.Context, c *cedarserver.Conn) error {
	req, err := message.NewMessageFromStream(c.Stream).GetClassAd(ctx)
	if err != nil {
		return err
	}
	f.mu.Lock()
	f.request = req
	f.mu.Unlock()

	constraint, _ := req.Lookup("Requirements")
	matchLimit, _ := req.EvaluateAttrInt("NumJobMatches")
	scanLimit, hasScanLimit := req.EvaluateAttrInt("ScanLimit")

	send := func(ad *classad.ClassAd) error {
		m := message.NewMessageForStream(c.Stream)
		if err := m.PutClassAd(ctx, ad); err != nil {
			return err
		}
		return m.FinishMessage(ctx)
	}

	var adCount, matchCount int64
	for _, rec := range f.records {
		adCount++
		matched := true
		if constraint != nil {
			matched, _ = constraint.Eval(rec).BoolValue()
		}
		if matched {
			if err := send(rec); err != nil {
				return err
			}
			matchCount++
		}
		if (matchLimit > 0 && matchCount >= matchLimit) || (hasScanLimit && scanLimit > 0 && adCount >= scanLimit) {
			break
		}
	}

	final := classad.New()
	final.InsertAttr("Owner", 0)
	final.InsertAttr("NumMatches", matchCount)
	final.InsertAttr("MalformedAds", 0)
	if !f.omitAdCount {
		final.InsertAttr("AdCount", adCount)
	}
	return send(final)
}

func (f *fakeHistoryDaemon) lastRequest() *classad.ClassAd {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.request
}

// historyRecords returns n completed-job records, newest first: ClusterId n
// is the newest and ClusterId 1 the oldest.
func historyRecords(n int) []*classad.ClassAd {
	out := make([]*classad.ClassAd, 0, n)
	for c := n; c >= 1; c-- {
		ad := classad.New()
		ad.InsertAttr("ClusterId", int64(c))
		ad.InsertAttr("ProcId", 0)
		ad.InsertAttr("JobStatus", 4)
		out = append(out, ad)
	}
	return out
}

// The bug this guards: on a busy access point the default scan limit is
// exhausted long before a query reaches an old time window, and the schedd
// answers with zero records. The records alone cannot tell that apart from
// "nothing matched"; the stats must.
func TestQueryHistoryReportsScanLimitReached(t *testing.T) {
	f := newFakeHistoryDaemon(t, historyRecords(100), false)
	s := NewSchedd("fake", f.addr)

	var st HistoryScanStats
	ads, err := s.QueryHistoryWithOptions(placementTestContext(t), "ClusterId <= 10", &HistoryQueryOptions{
		Limit:     3,
		ScanLimit: 50,
		Stats:     &st,
	})
	if err != nil {
		t.Fatalf("QueryHistoryWithOptions: %v", err)
	}
	if len(ads) != 0 {
		t.Fatalf("got %d records, want 0 (every match is older than the scan limit)", len(ads))
	}
	want := HistoryScanStats{Reported: true, RecordsScanned: 50, Matches: 0, ScanLimit: 50, ScanLimitReached: true}
	if st != want {
		t.Errorf("stats = %+v, want %+v", st, want)
	}

	// Without a scan limit the same query reaches the old records. (A
	// fresh daemon: the fake serves one connection per listener well.)
	s = NewSchedd("fake", newFakeHistoryDaemon(t, historyRecords(100), false).addr)
	st = HistoryScanStats{}
	ads, err = s.QueryHistoryWithOptions(placementTestContext(t), "ClusterId <= 10", &HistoryQueryOptions{
		Limit:     3,
		ScanLimit: -1,
		Stats:     &st,
	})
	if err != nil {
		t.Fatalf("QueryHistoryWithOptions (unlimited scan): %v", err)
	}
	if len(ads) != 3 {
		t.Fatalf("got %d records, want 3", len(ads))
	}
	if st.ScanLimitReached || st.ScanLimit != 0 || st.RecordsScanned != 93 || st.Matches != 3 {
		t.Errorf("unlimited scan: stats = %+v, want 93 scanned, 3 matches, not reached", st)
	}
}

// A scan that fills the match limit on the very record that also exhausts
// the scan limit was stopped by the match limit as far as the caller is
// concerned: every record it asked for is there.
func TestQueryHistoryMatchLimitIsNotAScanCutoff(t *testing.T) {
	f := newFakeHistoryDaemon(t, historyRecords(20), false)
	s := NewSchedd("fake", f.addr)

	var st HistoryScanStats
	ads, err := s.QueryHistoryWithOptions(placementTestContext(t), "true", &HistoryQueryOptions{
		Limit:     5,
		ScanLimit: 5,
		Stats:     &st,
	})
	if err != nil {
		t.Fatalf("QueryHistoryWithOptions: %v", err)
	}
	if len(ads) != 5 {
		t.Fatalf("got %d records, want 5", len(ads))
	}
	if !st.Reported || st.RecordsScanned != 5 || st.ScanLimitReached {
		t.Errorf("stats = %+v, want 5 scanned and the scan limit not reported as reached", st)
	}
}

// With no ScanLimit set the query goes out with DefaultHistoryScanLimit, and
// the stats say so.
func TestQueryHistoryDefaultScanLimit(t *testing.T) {
	f := newFakeHistoryDaemon(t, historyRecords(10), false)
	s := NewSchedd("fake", f.addr)

	var st HistoryScanStats
	if _, err := s.QueryHistoryWithOptions(placementTestContext(t), "true", &HistoryQueryOptions{Stats: &st}); err != nil {
		t.Fatalf("QueryHistoryWithOptions: %v", err)
	}
	if got, _ := f.lastRequest().EvaluateAttrInt("ScanLimit"); got != DefaultHistoryScanLimit {
		t.Errorf("request ScanLimit = %d, want %d", got, DefaultHistoryScanLimit)
	}
	if st.ScanLimit != DefaultHistoryScanLimit || st.RecordsScanned != 10 || st.ScanLimitReached {
		t.Errorf("stats = %+v, want scan limit %d, 10 scanned, not reached", st, DefaultHistoryScanLimit)
	}
}

// A daemon that sends no AdCount gives no basis for a conclusion either way.
func TestQueryHistoryWithoutAdCount(t *testing.T) {
	f := newFakeHistoryDaemon(t, historyRecords(100), true)
	s := NewSchedd("fake", f.addr)

	var st HistoryScanStats
	if _, err := s.QueryHistoryWithOptions(placementTestContext(t), "ClusterId <= 10", &HistoryQueryOptions{
		Limit: 3, ScanLimit: 50, Stats: &st,
	}); err != nil {
		t.Fatalf("QueryHistoryWithOptions: %v", err)
	}
	if st.Reported || st.ScanLimitReached {
		t.Errorf("stats = %+v, want nothing reported", st)
	}
}

// The streaming query fills Stats before closing its channel.
func TestQueryHistoryStreamReportsScanLimitReached(t *testing.T) {
	f := newFakeHistoryDaemon(t, historyRecords(100), false)
	s := NewSchedd("fake", f.addr)

	var st HistoryScanStats
	ch, err := s.QueryHistoryStream(placementTestContext(t), "ClusterId <= 10", &HistoryQueryOptions{
		Limit: 3, ScanLimit: 50, Stats: &st,
	}, nil)
	if err != nil {
		t.Fatalf("QueryHistoryStream: %v", err)
	}
	n := 0
	for r := range ch {
		if r.Err != nil {
			t.Fatalf("stream: %v", r.Err)
		}
		n++
	}
	if n != 0 || !st.ScanLimitReached || st.RecordsScanned != 50 {
		t.Errorf("got %d records, stats %+v; want 0 records and the scan limit reached after 50", n, st)
	}
}

func TestHistoryScanStatsFromClosingAd(t *testing.T) {
	final := func(matches, scanned int64) *classad.ClassAd {
		ad := classad.New()
		ad.InsertAttr("Owner", 0)
		ad.InsertAttr("NumMatches", matches)
		ad.InsertAttr("MalformedAds", 1)
		ad.InsertAttr("AdCount", scanned)
		return ad
	}
	for _, tc := range []struct {
		name               string
		limit, scanLimit   int
		matches, scanned   int64
		reached, malformed bool
	}{
		{"cut off with no matches", 50, 10000, 0, 10000, true, true},
		{"cut off with some matches", 50, 10000, 7, 10000, true, true},
		{"match limit filled", 50, 10000, 50, 10000, false, true},
		{"history exhausted first", 50, 10000, 7, 4000, false, true},
		{"no scan limit", 50, 0, 7, 10000, false, true},
		{"unlimited matches, cut off", -1, 100, 7, 100, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := historyScanStats(final(tc.matches, tc.scanned), &HistoryQueryOptions{Limit: tc.limit, ScanLimit: tc.scanLimit})
			if st.ScanLimitReached != tc.reached {
				t.Errorf("ScanLimitReached = %v, want %v (%+v)", st.ScanLimitReached, tc.reached, st)
			}
			if !st.Reported || st.RecordsScanned != int(tc.scanned) || st.Matches != int(tc.matches) || st.MalformedAds != 1 {
				t.Errorf("counts wrong: %+v", st)
			}
		})
	}
}
