package multiap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/dbrpc"

	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/jobid"
	"github.com/bbockelm/golang-htcondor/webapi/apregistry"
	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
	"github.com/bbockelm/golang-htcondor/webapi/ownerscope"
)

// StaleMode says what an unscoped read does with a degraded AP's rows.
type StaleMode string

const (
	// StaleInclude returns a degraded AP's rows as the hub holds them,
	// flagged in the sources block. The default.
	StaleInclude StaleMode = "include"
	// StaleExclude drops a degraded AP's rows; the AP is still listed in
	// the sources block.
	StaleExclude StaleMode = "exclude"
)

// ParseStaleMode reads HTTP_API_MULTI_AP_STALE. Empty is StaleInclude.
func ParseStaleMode(v string) (StaleMode, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", string(StaleInclude):
		return StaleInclude, nil
	case string(StaleExclude):
		return StaleExclude, nil
	}
	return "", fmt.Errorf("HTTP_API_MULTI_AP_STALE must be %q or %q, not %q", StaleInclude, StaleExclude, v)
}

// Registry is the AP set. *apregistry.Registry satisfies it.
type Registry interface {
	Members() []apregistry.Member
	Get(name string) (apregistry.Member, bool)
}

// SpokeSource finds and dials per-AP mirrors. *dbmirror.Locator
// satisfies it.
type SpokeSource interface {
	Spokes(ctx context.Context) (*dbmirror.SpokeSet, error)
	ClientFor(ctx context.Context, info *dbmirror.Info) (*dbrpc.Client, func(), error)
}

// ScheddQuerier is the schedd read a single-job fallback makes, as the
// caller. *htcondor.Schedd satisfies it.
type ScheddQuerier interface {
	QueryWithOptions(ctx context.Context, constraint string, opts *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error)
}

// NoSchedd is what the single-schedd accessors return in multi-AP mode,
// where there is no single schedd. Its address does not parse, so any
// call through it fails at dial time without touching the network.
var NoSchedd = htcondor.NewSchedd("multi-ap-mode", "multi-AP mode has no single schedd")

// Service answers multi-AP reads.
type Service struct {
	Registry Registry
	Hub      *Hub
	// Spokes is optional; without it a stale AP's single-job read goes
	// straight to its schedd.
	Spokes SpokeSource
	// Schedd returns the querier for a member. Nil uses the member's
	// *htcondor.Schedd.
	Schedd func(m apregistry.Member) ScheddQuerier
	Codec  jobid.Codec
	Stale  StaleMode
	// UIDDomain completes a bare owner into the User attribute value.
	UIDDomain string
}

// Error is a failure with the HTTP status it maps to.
type Error struct {
	Status int
	Msg    string
	// Candidates is set on an ambiguous incomplete job id (409).
	Candidates []JobRef
}

func (e *Error) Error() string { return e.Msg }

func errorf(status int, format string, args ...any) *Error {
	return &Error{Status: status, Msg: fmt.Sprintf(format, args...)}
}

// StatusOf maps an error from this package to an HTTP status.
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return http.StatusInternalServerError
}

// UserFor returns the value of the User job attribute for an
// authenticated actor: the bare owner (everything before the LAST "@",
// since "@" is legal in a Linux username) and this pool's UID_DOMAIN.
// Multi-AP v1 requires every member to share one UID_DOMAIN, so the
// attribute is the same on every AP.
func (s *Service) UserFor(actor string) (string, error) {
	owner := actor
	if i := strings.LastIndex(actor, "@"); i >= 0 {
		owner = actor[:i]
	}
	if owner == "" {
		return "", errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	if s.UIDDomain == "" {
		return "", errorf(http.StatusInternalServerError, "UID_DOMAIN is not configured")
	}
	return owner + "@" + s.UIDDomain, nil
}

// --- sources --------------------------------------------------------------

// Degraded is one AP whose rows are not known to be fresh.
type Degraded struct {
	Schedd           string `json:"schedd"`
	State            string `json:"state"`
	StalenessSeconds *int64 `json:"staleness_seconds,omitempty"`
	LastSeen         string `json:"last_seen,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

// Sources is the block every multi-AP read response carries.
type Sources struct {
	APs      int        `json:"aps"`
	Fresh    int        `json:"fresh"`
	Degraded []Degraded `json:"degraded"`
}

// view is one read's picture of the AP set.
type view struct {
	sources Sources
	// members is every AP in the set, by lower-cased name.
	members map[string]apregistry.Member
	// fresh is which of them the hub holds fresh.
	fresh map[string]bool
}

// snapshot computes the AP set and its freshness. The AP set is the
// registry's: an AP the hub does not list is absent, never omitted, and
// hub rows for a schedd outside the set are not served.
func (s *Service) snapshot() view {
	v := view{members: map[string]apregistry.Member{}, fresh: map[string]bool{}}
	v.sources.Degraded = []Degraded{}
	reachable := s.Hub.Status().Reachable
	for _, m := range s.Registry.Members() {
		key := strings.ToLower(m.Name)
		v.members[key] = m
		v.sources.APs++
		src, ok := s.Hub.Source(m.Name)
		switch {
		case ok && src.State == StateFresh:
			v.fresh[key] = true
			v.sources.Fresh++
			continue
		case ok:
			d := Degraded{Schedd: m.Name, State: src.State, Reason: src.Reason}
			if src.StalenessKnown {
				st := src.Staleness
				d.StalenessSeconds = &st
			}
			if !src.LastSeen.IsZero() {
				d.LastSeen = src.LastSeen.Format(time.RFC3339)
			}
			v.sources.Degraded = append(v.sources.Degraded, d)
		case !reachable:
			v.sources.Degraded = append(v.sources.Degraded, Degraded{
				Schedd: m.Name, State: StateStale, Reason: "the federation hub is not answering",
			})
		default:
			v.sources.Degraded = append(v.sources.Degraded, Degraded{
				Schedd: m.Name, State: StateAbsent, Reason: "the federation hub does not hold this access point",
			})
		}
	}
	return v
}

// Sources reports the AP set's freshness, for a response that serves no
// rows of its own.
func (s *Service) Sources() Sources { return s.snapshot().sources }

// allowed is the set of APs a read may return rows from: the requested
// one, or every member, minus degraded APs when StaleExclude is set.
func (s *Service) allowed(v view, schedd string) ([]string, error) {
	var names []string
	if schedd != "" {
		m, ok := v.members[strings.ToLower(schedd)]
		if !ok {
			return nil, errorf(http.StatusBadRequest, "%q is not an access point this server serves", schedd)
		}
		names = []string{m.Name}
	} else {
		for _, m := range v.members {
			names = append(names, m.Name)
		}
	}
	if s.Stale == StaleExclude {
		kept := names[:0]
		for _, n := range names {
			if v.fresh[strings.ToLower(n)] {
				kept = append(kept, n)
			}
		}
		names = kept
	}
	sort.Strings(names)
	return names, nil
}

// scoped builds the hub constraint: the caller's constraint confined to
// their own jobs (the shared parse-and-reserialize AND, keyed on User)
// and to the allowed APs. The hub has no row-level ACL; this clause is
// the scope.
func scoped(user, constraint string, schedds []string) (string, error) {
	base, err := ownerscope.Constrain("User", user, constraint)
	if err != nil {
		return "", errorf(http.StatusBadRequest, "invalid constraint: %v", err)
	}
	return fmt.Sprintf("(%s) && (%s)", base, scheddIn(schedds)), nil
}

func scheddIn(schedds []string) string {
	if len(schedds) == 0 {
		return "false"
	}
	parts := make([]string, len(schedds))
	for i, n := range schedds {
		parts[i] = AttrScheddName + " == " + ownerscope.StringLit(n)
	}
	return strings.Join(parts, " || ")
}

// --- rows -----------------------------------------------------------------

// JobRef names one job, for a 409's candidate list.
type JobRef struct {
	Schedd   string `json:"schedd"`
	Cluster  int64  `json:"cluster"`
	Proc     int64  `json:"proc"`
	JobID    string `json:"job_id"`
	Archived bool   `json:"archived"`
}

// Row is one job ad and its identity.
type Row struct {
	ID       jobid.ID
	Ad       *classad.ClassAd
	Archived bool
}

// Ref is the row's identity, for JSON.
func (s *Service) Ref(r Row) JobRef {
	return JobRef{Schedd: r.ID.Schedd, Cluster: r.ID.Cluster, Proc: r.ID.Proc, JobID: s.Codec.Format(r.ID), Archived: r.Archived}
}

// reservedKeys are the members RowJSON adds to a job ad. An attribute of
// the same name (any case) is dropped from the ad so the object never
// carries two spellings of one member.
var reservedKeys = []string{"schedd", "cluster", "proc", "job_id", "archived"}

// RowJSON renders a row as the ad's JSON object with the job's identity
// as separate members: schedd, cluster, proc, and job_id (the codec's
// text form, for the one place a single token is needed: a URL).
func (s *Service) RowJSON(r Row) ([]byte, error) {
	for _, k := range reservedKeys {
		for _, name := range r.Ad.GetAttributes() {
			if strings.EqualFold(name, k) {
				r.Ad.Delete(name)
			}
		}
	}
	adJSON, err := json.Marshal(r.Ad)
	if err != nil {
		return nil, err
	}
	head, err := json.Marshal(s.Ref(r))
	if err != nil {
		return nil, err
	}
	adJSON = bytes.TrimSpace(adJSON)
	if len(adJSON) < 2 || adJSON[0] != '{' {
		return nil, fmt.Errorf("job ad did not encode as an object")
	}
	body := bytes.TrimSpace(adJSON[1:])
	out := make([]byte, 0, len(head)+len(adJSON)+1)
	out = append(out, head[:len(head)-1]...)
	if len(body) > 1 { // more than the closing brace
		out = append(out, ',')
	}
	out = append(out, body...)
	return out, nil
}

// rowFromText parses a hub row. A row with no ScheddName, ClusterId or
// ProcId cannot be named, so it is an error rather than a row with a
// made-up identity.
func rowFromText(text, schedd string) (Row, error) {
	ad, err := classad.ParseOld(text)
	if err != nil {
		return Row{}, fmt.Errorf("unparseable row: %w", err)
	}
	if schedd == "" {
		schedd, _ = ad.EvaluateAttrString(AttrScheddName)
	}
	c, okc := ad.EvaluateAttrInt("ClusterId")
	p, okp := ad.EvaluateAttrInt("ProcId")
	if schedd == "" || !okc || !okp {
		return Row{}, fmt.Errorf("row lacks ScheddName, ClusterId or ProcId")
	}
	return Row{ID: jobid.ID{Schedd: schedd, Cluster: c, Proc: p}, Ad: ad}, nil
}

// keyAttrs are what a projected read must carry to name its rows.
var keyAttrs = []string{AttrScheddName, "ClusterId", "ProcId"}

// projectionWith returns projection plus attrs. A nil or "*" projection
// means every attribute and stays nil.
func projectionWith(projection []string, attrs ...string) []string {
	if len(projection) == 0 {
		return nil
	}
	out := make([]string, 0, len(projection)+len(attrs))
	for _, a := range projection {
		if a == "*" {
			return nil
		}
		out = append(out, a)
	}
	for _, a := range attrs {
		dup := false
		for _, have := range out {
			dup = dup || strings.EqualFold(have, a)
		}
		if !dup {
			out = append(out, a)
		}
	}
	return out
}

// --- live jobs ------------------------------------------------------------

// ListRequest is a list read.
type ListRequest struct {
	// User is the caller's User attribute value (see UserFor). Required.
	User       string
	Constraint string
	Projection []string
	// Limit is the page size; non-positive means the ceiling.
	Limit     int
	PageToken string
	// Schedd restricts the read to one AP.
	Schedd string
}

// ListResult describes a list read once its rows have been yielded.
type ListResult struct {
	Sources       Sources
	Returned      int
	HasMore       bool
	NextPageToken string
	// Err is a failure after some rows were already yielded; the caller
	// reports it inside the response it has started.
	Err error
}

// ListJobs streams the caller's live jobs from the hub. It returns an
// error only before yielding anything.
func (s *Service) ListJobs(ctx context.Context, req ListRequest, yield func(Row) bool) (*ListResult, error) {
	if req.User == "" {
		return nil, errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	var cursor dbrpc.SeqCursor
	if req.PageToken != "" {
		if !dbmirror.IsCursor(req.PageToken) {
			return nil, errorf(http.StatusBadRequest, "this page token was not issued for the multi-AP job list")
		}
		c, err := dbmirror.DecodeCursor(req.PageToken)
		if err != nil {
			return nil, errorf(http.StatusBadRequest, "unreadable page token: %v", err)
		}
		cursor = c
	}
	v := s.snapshot()
	res := &ListResult{Sources: v.sources}
	schedds, err := s.allowed(v, req.Schedd)
	if err != nil {
		return nil, err
	}
	if len(schedds) == 0 {
		return res, nil
	}
	constraint, err := scoped(req.User, req.Constraint, schedds)
	if err != nil {
		return nil, err
	}
	dbc, closer, err := s.Hub.Client(ctx)
	if err != nil {
		return nil, errorf(http.StatusServiceUnavailable, "the federation hub is unavailable: %v", err)
	}
	defer closer()

	limit := dbmirror.ClampLimit(req.Limit, dbmirror.Projected(req.Projection))
	var rowErr error
	stopped := false
	page, err := dbc.QueryRawProjectedFromSeqStream(ctx, TableJobs, constraint,
		projectionWith(req.Projection, keyAttrs...), cursor, limit, func(text string) bool {
			row, perr := rowFromText(text, "")
			if perr != nil {
				rowErr = perr
				return false
			}
			res.Returned++
			if !yield(row) {
				stopped = true
				return false
			}
			return true
		})
	if err == nil {
		err = rowErr
	}
	if err != nil {
		if res.Returned == 0 && !stopped {
			return nil, errorf(http.StatusServiceUnavailable, "reading the federation hub: %v", err)
		}
		res.Err = err
		return res, nil
	}
	if page != nil && page.More && !stopped {
		res.HasMore = true
		res.NextPageToken = dbmirror.EncodeCursor(page.Next)
	}
	return res, nil
}
