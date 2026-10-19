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
	"sync"
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
	// QueueSuperUser reports whether actor is in schedd's
	// QUEUE_SUPER_USERS, as read from that AP. Cross-user power is per
	// AP: nil means nobody is a superuser anywhere.
	QueueSuperUser func(schedd, actor string) bool
	// HubStateInterval is the hub's HTCONDORDB_FEDERATE_STATE_INTERVAL,
	// which bounds how far a federation_sources row lags the hub's own
	// state; zero is DefaultHubStateInterval.
	HubStateInterval time.Duration
	// BulkFresh is HTTP_API_BULK_FRESH_SECONDS, for bulk actions this
	// service's callers fan out; zero or negative never skips an AP.
	BulkFresh time.Duration
	// Admit, when set, is each AP's own verdict on a caller: an error
	// refuses anything routed to that AP for user (an account disabled
	// there, say). Route, share redemption and every bulk leg ask it. A
	// grant is good at every AP; this is how one AP's decision still
	// holds on that AP.
	Admit func(ctx context.Context, m apregistry.Member, user string) error
	// VerifyCaller, when set, confirms that the AP a call was routed to
	// identifies ctx's credential as user; MCP runs it on every routed
	// call, so the identity an action runs as is the routed AP's.
	VerifyCaller func(ctx context.Context, m apregistry.Member, user string) error
	// Assign places new submissions (AP assignment); nil refuses them.
	Assign Assigner
	// Now replaces the clock, for tests.
	Now func() time.Time

	writesMu sync.Mutex
	writes   map[string]time.Time // last write by this server, per lower-cased AP
}

// IsQueueSuperUser reports whether actor is a queue superuser on schedd.
func (s *Service) IsQueueSuperUser(schedd, actor string) bool {
	return s != nil && s.QueueSuperUser != nil && schedd != "" && actor != "" && s.QueueSuperUser(schedd, actor)
}

// Error is a failure with the HTTP status it maps to.
type Error struct {
	Status int
	Msg    string
	// Reason is a machine-readable cause (Reason* constants), when one
	// applies.
	Reason string
	// Candidates is set on an ambiguous incomplete job id (409), and on
	// an incomplete one given to a mutation (400).
	Candidates []JobRef
}

func asError(err error, target **Error) bool { return errors.As(err, target) }

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
// authenticated actor. Multi-AP v1 requires every member to share one
// UID_DOMAIN, so the attribute is the same on every AP.
//
// The actor's domain is everything after the LAST "@" ("@" is legal in a
// Linux username), as HTCondor's domain_of_user splits it. A bare name, or
// HTCondor's "name@." spelling of the local domain, gets UID_DOMAIN. A
// qualified name must be in UID_DOMAIN, compared as HTCondor compares
// domains (is_same_domain with COMPARE_DOMAIN_FULL: case-insensitive,
// whole string); any other domain is refused rather than rewritten,
// because alice@elsewhere is not alice@UID_DOMAIN and must not read her
// jobs.
func (s *Service) UserFor(actor string) (string, error) {
	if s.UIDDomain == "" {
		return "", errorf(http.StatusInternalServerError, "UID_DOMAIN is not configured")
	}
	owner, domain, qualified := actor, "", false
	if i := strings.LastIndex(actor, "@"); i >= 0 {
		owner, domain, qualified = actor[:i], actor[i+1:], true
	}
	if owner == "" {
		return "", errorf(http.StatusUnauthorized, "the caller's identity could not be established")
	}
	if qualified && domain != "." && !strings.EqualFold(domain, s.UIDDomain) {
		return "", errorf(http.StatusForbidden,
			"%q is in the domain %q, but the access points behind this server use UID_DOMAIN %q", actor, domain, s.UIDDomain)
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
	// Hub names the federation hub the read was served from (its
	// collector ad Name), when there is one to name. Every count and
	// state here is that hub's.
	Hub      string     `json:"hub,omitempty"`
	APs      int        `json:"aps"`
	Fresh    int        `json:"fresh"`
	Degraded []Degraded `json:"degraded"`
	// NotKept lists the APs that keep no copy of a table a read used
	// (TableSources): they have no such rows, which is not a fault.
	NotKept []NotKept `json:"not_kept,omitempty"`
}

// NotKept is one AP that keeps no copy of a table.
type NotKept struct {
	Schedd string `json:"schedd"`
	Table  string `json:"table"`
	Reason string `json:"reason,omitempty"`
}

// view is one read's picture of the AP set, from one hub.
type view struct {
	// hub is the hub the picture is of, and the one the read queries.
	hub     *HubEndpoint
	sources Sources
	// members is every AP in the set, by lower-cased name.
	members map[string]apregistry.Member
	// fresh is which of them the hub holds fresh.
	fresh map[string]bool
	// settling is which of them the hub holds fresh but has held for
	// less than the settle window since a switch made it active.
	settling map[string]bool
}

// snapshot computes the AP set and its freshness on the hub ctx is
// pinned to (else the active one). The AP set is the registry's: an AP
// the hub does not list is absent, never omitted, and hub rows for a
// schedd outside the set are not served.
func (s *Service) snapshot(ctx context.Context) view {
	ep := s.Hub.For(ctx)
	v := view{hub: ep, members: map[string]apregistry.Member{}, fresh: map[string]bool{}, settling: map[string]bool{}}
	sw, settling := s.Hub.Settling(ctx)
	v.sources.Hub = ep.Name()
	v.sources.Degraded = []Degraded{}
	reachable := ep.Status().Reachable
	for _, m := range s.Registry.Members() {
		key := strings.ToLower(m.Name)
		v.members[key] = m
		v.sources.APs++
		src, ok := ep.Source(m.Name)
		if m.Untrusted() {
			// The hub's copy may well be current, and reads still serve
			// it; but nothing can be done on this AP, and a caller
			// looking at its jobs must be told that.
			v.fresh[key] = ok && src.State == StateFresh
			v.sources.Degraded = append(v.sources.Degraded, Degraded{
				Schedd: m.Name, State: StateUntrusted, Reason: untrustedReason(m),
			})
			continue
		}
		switch {
		case ok && src.State == StateFresh && settling:
			v.settling[key] = true
			v.sources.Degraded = append(v.sources.Degraded, Degraded{
				Schedd: m.Name, State: StateSettling, Reason: s.settlingReason(sw),
			})
			continue
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

// settlingReason is the sources-block reason for an AP on a hub that
// became active less than the settle window ago.
func (s *Service) settlingReason(sw HubSwitch) string {
	from := sw.From
	if from == "" {
		from = "the previous hub"
	}
	return fmt.Sprintf("reads moved to federation hub %s from %s at %s (%s); until %s its copy may lack changes %s had",
		sw.To, from, sw.At.UTC().Format(time.RFC3339), sw.Reason,
		s.Hub.SettleUntil(sw).UTC().Format(time.RFC3339), from)
}

// untrustedReason is the sources-block reason for an AP that failed its
// trust probe.
func untrustedReason(m apregistry.Member) string {
	if m.Trust.Reason == "" {
		return untrustedMessage
	}
	return untrustedMessage + ": " + m.Trust.Reason
}

// Sources reports the AP set's freshness on the hub ctx is pinned to
// (else the active one), for a response that serves no rows of its own.
func (s *Service) Sources(ctx context.Context) Sources { return s.snapshot(ctx).sources }

// noteRead records a data read's outcome against the hub ctx is pinned
// to (HubEndpoint.NoteRead), and returns err.
func (s *Service) noteRead(ctx context.Context, err error) error {
	s.Hub.For(ctx).NoteRead(ctx, err)
	return err
}

// NoteHubRead is noteRead for a caller reading through HubClient.
func (s *Service) NoteHubRead(ctx context.Context, err error) { _ = s.noteRead(ctx, err) }

// PinHub returns ctx pinned to the active federation hub: every read
// made with it is served from, and reports the freshness of, that one
// hub, even if another becomes active meanwhile. A request pins once, so
// its reads never mix two hubs' answers.
func (s *Service) PinHub(ctx context.Context) context.Context { return s.Hub.Pin(ctx) }

// HubOrigin names the hub ctx is pinned to and the selection generation
// it was pinned in (see Hub.Origin).
func (s *Service) HubOrigin(ctx context.Context) string { return s.Hub.Origin(ctx) }

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
			// A settling AP's rows are the hub's current copy, not a
			// degraded source's: they stay.
			if k := strings.ToLower(n); v.fresh[k] || v.settling[k] {
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
	ctx = s.PinHub(ctx)
	v := s.snapshot(ctx)
	var cursor dbrpc.SeqCursor
	if req.PageToken != "" {
		c, err := decodeJobsToken(req.PageToken, v.hub.Name())
		if err != nil {
			return nil, err
		}
		cursor = c
	}
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
	dbc, closer, err := v.hub.Client(ctx)
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
	if s.noteRead(ctx, err) == nil {
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
		res.NextPageToken = encodeJobsToken(v.hub.Name(), page.Next)
	}
	return res, nil
}
