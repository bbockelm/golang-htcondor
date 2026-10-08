package multiap

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// History pagination.
//
// The single-AP keyset, (ClusterId, ProcId), is not unique across APs:
// two APs both have a 123.0. The hub's history is therefore paged on
// (EnteredHistoryTime, ScheddName, ClusterId, ProcId), newest first, under
// a "hub1:" token that the single-AP endpoints refuse (and this one
// refuses theirs).
//
// The archive returns rows in append order, which across fifty APs is not
// EnteredHistoryTime order: a spoke catching up appends old records late.
// So a page is not "the first N rows the archive yields". It is built
// from a server-side TopK on EnteredHistoryTime -- every row strictly
// newer than the K-th value is among the K returned -- plus every row
// tied at that boundary value, sorted on the whole key and cut at N. The
// cut never splits rows with an identical key. Rows with no
// EnteredHistoryTime sort after every row that has one, ordered by
// (ScheddName, ClusterId, ProcId).
//
// ScheddName is ordered with strcmp (byte order), the same comparison the
// Go side sorts with; ClassAd's "<" on strings ignores case and would
// disagree.

const (
	historyTokenPrefix = "hub1:"
	attrEnteredHistory = "EnteredHistoryTime"
	// maxBoundaryRows caps one page's tie set (rows sharing the boundary
	// EnteredHistoryTime, or lacking one). Past it the page cannot be
	// ordered exactly, which is an error rather than a guess.
	maxBoundaryRows = 20000
)

// histKey orders history rows, newest first.
type histKey struct {
	// Undef is set for rows with no EnteredHistoryTime, which sort last.
	Undef bool   `json:"u,omitempty"`
	T     int64  `json:"t"`
	S     string `json:"s"`
	C     int64  `json:"c"`
	P     int64  `json:"p"`
}

// before reports whether a sorts before b: newer first.
func (a histKey) before(b histKey) bool {
	if a.Undef != b.Undef {
		return !a.Undef
	}
	if a.T != b.T {
		return a.T > b.T
	}
	if a.S != b.S {
		return a.S > b.S
	}
	if a.C != b.C {
		return a.C > b.C
	}
	return a.P > b.P
}

// IsHistoryToken reports whether a page token is a multi-AP history
// token.
func IsHistoryToken(token string) bool { return strings.HasPrefix(token, historyTokenPrefix) }

func encodeHistoryToken(k histKey) string {
	raw, _ := json.Marshal(k) // a struct of scalars; cannot fail
	return historyTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func decodeHistoryToken(token string) (histKey, error) {
	if !IsHistoryToken(token) {
		return histKey{}, fmt.Errorf("not a multi-AP history page token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token[len(historyTokenPrefix):])
	if err != nil {
		return histKey{}, err
	}
	var k histKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return histKey{}, err
	}
	return k, nil
}

// tupleBefore is the ClassAd predicate "(ScheddName, ClusterId, ProcId)
// sorts after k" in newest-first order, i.e. is strictly smaller.
func tupleBefore(k histKey) string {
	s := strLit(k.S)
	return fmt.Sprintf("(strcmp(ScheddName, %s) < 0 || (strcmp(ScheddName, %s) == 0 && (ClusterId < %d || (ClusterId == %d && ProcId < %d))))",
		s, s, k.C, k.C, k.P)
}

// definedAfter selects rows with an EnteredHistoryTime that come after k.
func definedAfter(k *histKey) string {
	if k == nil {
		return attrEnteredHistory + " isnt undefined"
	}
	return fmt.Sprintf("(%s isnt undefined && (%s < %d || (%s == %d && %s)))",
		attrEnteredHistory, attrEnteredHistory, k.T, attrEnteredHistory, k.T, tupleBefore(*k))
}

// undefinedAfter selects rows without an EnteredHistoryTime that come
// after k.
func undefinedAfter(k *histKey) string {
	base := attrEnteredHistory + " is undefined"
	if k == nil || !k.Undef {
		return base
	}
	return fmt.Sprintf("(%s && %s)", base, tupleBefore(*k))
}

func strLit(s string) string {
	b, _ := json.Marshal(s) // JSON string escaping is valid ClassAd string syntax for these names
	return string(b)
}

type histRow struct {
	key histKey
	row Row
}

// ListHistory returns one page of the caller's completed jobs from the
// hub's history archive, newest first.
func (s *Service) ListHistory(ctx context.Context, req ListRequest) ([]Row, *ListResult, error) {
	if req.User == "" {
		return nil, nil, errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	var after *histKey
	if req.PageToken != "" {
		k, err := decodeHistoryToken(req.PageToken)
		if err != nil {
			return nil, nil, errorf(http.StatusBadRequest, "this page token was not issued for the multi-AP history: %v", err)
		}
		after = &k
	}
	v := s.snapshot()
	res := &ListResult{Sources: v.sources}
	schedds, err := s.allowed(v, req.Schedd)
	if err != nil {
		return nil, nil, err
	}
	if len(schedds) == 0 {
		return nil, res, nil
	}
	scope, err := scoped(req.User, req.Constraint, schedds)
	if err != nil {
		return nil, nil, err
	}
	dbc, closer, err := s.Hub.Client(ctx)
	if err != nil {
		return nil, nil, errorf(http.StatusServiceUnavailable, "the federation hub is unavailable: %v", err)
	}
	defer closer()

	limit := dbmirror.ClampLimit(req.Limit, dbmirror.Projected(req.Projection))
	// The page is chosen on the key alone; whole ads (no projection) are
	// fetched afterwards for just that key range. TopK returns only the
	// attributes it is asked for, so "every attribute" cannot ride on it.
	keyProj := append([]string{attrEnteredHistory}, keyAttrs...)
	proj := projectionWith(req.Projection, keyProj...)
	if proj == nil {
		proj = keyProj
	}
	and := func(c string) string { return "(" + scope + ") && " + c }

	var rows []histRow
	if after == nil || !after.Undef {
		// One past the page: more than limit rows back says the defined
		// region does not end on this page.
		top, err := s.historyQuery(func(yield func(string) bool) error {
			texts, err := dbc.TopK(ctx, TableHistory, and(definedAfter(after)), proj, attrEnteredHistory, true, limit+1)
			if err != nil {
				return err
			}
			for _, t := range texts {
				if !yield(t) {
					break
				}
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
		if len(top) > limit {
			// Every row newer than the smallest value returned is in top;
			// the rows AT that value are not necessarily all there, so
			// fetch them.
			tmin := top[0].key.T
			for _, r := range top {
				if r.key.T < tmin {
					tmin = r.key.T
				}
			}
			kept := make([]histRow, 0, len(top))
			for _, r := range top {
				if r.key.T > tmin {
					kept = append(kept, r)
				}
			}
			ties, err := s.historyScan(ctx, dbc, and(fmt.Sprintf("(%s && %s == %d)", definedAfter(after), attrEnteredHistory, tmin)), proj)
			if err != nil {
				return nil, nil, err
			}
			out, res := cutHistory(append(kept, ties...), limit, res)
			if !res.HasMore && len(out) > 0 {
				// Rows older than the boundary may remain; an empty last
				// page is the price of never dropping them.
				res.HasMore = true
				res.NextPageToken = encodeHistoryToken(keyOf(out[len(out)-1]))
			}
			return s.wholeAds(ctx, dbc, scope, after, out, req.Projection, res)
		}
		rows = top
	}
	// The defined region ends on this page; continue into the rows with
	// no EnteredHistoryTime. Every remaining candidate is now in hand.
	undef, err := s.historyScan(ctx, dbc, and(undefinedAfter(after)), proj)
	if err != nil {
		return nil, nil, err
	}
	out, res := cutHistory(append(rows, undef...), limit, res)
	return s.wholeAds(ctx, dbc, scope, after, out, req.Projection, res)
}

// afterKey selects rows strictly after k in newest-first order.
func afterKey(k *histKey) string {
	switch {
	case k == nil:
		return "true"
	case k.Undef:
		return undefinedAfter(k)
	default:
		return fmt.Sprintf("(%s || %s is undefined)", definedAfter(k), attrEnteredHistory)
	}
}

// wholeAds replaces a page chosen on its keys with the full rows of that
// key range, when the caller asked for every attribute. A record that
// arrived in between with a key inside the range is served here and, as
// the next page starts after the range, nowhere else.
func (s *Service) wholeAds(ctx context.Context, dbc *dbrpc.Client, scope string, after *histKey, page []Row, projection []string, res *ListResult) ([]Row, *ListResult, error) {
	if len(page) == 0 || projectionWith(projection, attrEnteredHistory) != nil {
		return page, res, nil
	}
	last := keyOf(page[len(page)-1])
	rows, err := s.historyScan(ctx, dbc, fmt.Sprintf("(%s) && %s && !%s", scope, afterKey(after), afterKey(&last)), nil)
	if err != nil {
		return nil, nil, err
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].key.before(rows[j].key) })
	out := make([]Row, len(rows))
	for i := range rows {
		out[i] = rows[i].row
	}
	res.Returned = len(out)
	return out, res, nil
}

// cutHistory sorts a page's candidate rows, keeps the first limit (never
// splitting identical keys) and sets the continuation token.
func cutHistory(rows []histRow, limit int, res *ListResult) ([]Row, *ListResult) {
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].key.before(rows[j].key) })
	n := len(rows)
	if n > limit {
		n = limit
		for n < len(rows) && rows[n].key == rows[n-1].key {
			n++
		}
	}
	out := make([]Row, n)
	for i := range n {
		out[i] = rows[i].row
	}
	res.Returned = n
	if n < len(rows) {
		res.HasMore = true
		res.NextPageToken = encodeHistoryToken(rows[n-1].key)
	}
	return out, res
}

// historyScan reads every row matching constraint, up to the boundary cap.
func (s *Service) historyScan(ctx context.Context, dbc *dbrpc.Client, constraint string, proj []string) ([]histRow, error) {
	rows, err := s.historyQuery(func(yield func(string) bool) error {
		return dbc.QueryRawProjectStream(ctx, TableHistory, constraint, proj, maxBoundaryRows+1, yield)
	})
	if err != nil {
		return nil, err
	}
	if len(rows) > maxBoundaryRows {
		return nil, errorf(http.StatusServiceUnavailable,
			"more than %d history records share one completion time; narrow the query", maxBoundaryRows)
	}
	return rows, nil
}

// historyQuery runs one read and parses its rows into keyed history rows.
func (s *Service) historyQuery(run func(yield func(string) bool) error) ([]histRow, error) {
	var out []histRow
	var perr error
	err := run(func(text string) bool {
		row, err := rowFromText(text, "")
		if err != nil {
			perr = err
			return false
		}
		row.Archived = true
		out = append(out, histRow{key: keyOf(row), row: row})
		return true
	})
	if err == nil {
		err = perr
	}
	if err != nil {
		return nil, errorf(http.StatusServiceUnavailable, "reading the federation hub's history: %v", err)
	}
	return out, nil
}

func keyOf(r Row) histKey {
	k := histKey{S: r.ID.Schedd, C: r.ID.Cluster, P: r.ID.Proc}
	if t, ok := evalNumber(r.Ad, attrEnteredHistory); ok {
		k.T = t
	} else {
		k.Undef = true
	}
	return k
}

func evalNumber(ad *classad.ClassAd, attr string) (int64, bool) {
	if v, ok := ad.EvaluateAttrInt(attr); ok {
		return v, true
	}
	if f, ok := ad.EvaluateAttrReal(attr); ok {
		return int64(f), true
	}
	return 0, false
}
