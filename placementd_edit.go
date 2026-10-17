package htcondor

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
)

// The placementd's typed query and edit commands (API version 2). They read
// and change the daemon's directory of identities, accounts, projects and
// authorizations. A placementd advertises PlacementdApiVersion >= 2 in its
// daemon ad when it serves them; an older daemon does not register them at
// all.

const (
	// PlacementQueryCommand is PLACEMENT_QUERY: a typed query over one
	// kind of directory entity, or the mapfile status.
	PlacementQueryCommand = commands.SCHED_VERS + 164
	// PlacementEditCommand is PLACEMENT_EDIT: an atomic batch of create,
	// update, delete and adopt operations.
	PlacementEditCommand = commands.SCHED_VERS + 165
)

// Error codes of the query and edit commands, continuing PlacementErr*.
const (
	// PlacementErrNotFound means a selector or a reference named no
	// entity.
	PlacementErrNotFound = 13
	// PlacementErrVersionMismatch means an operation's ExpectedVersion is
	// not the entity's current version: someone else changed it first.
	PlacementErrVersionMismatch = 14
	// PlacementErrOwnedBySource means the entity is owned by another
	// source (the mapfile) and only Adopt may change it.
	PlacementErrOwnedBySource = 15
	// PlacementErrInvalidArgument covers a bad attribute type, an empty
	// or uncanonical name, a DefaultProject outside Projects, or a batch
	// size out of range.
	PlacementErrInvalidArgument = 16
	// PlacementErrStillReferenced means a Delete would orphan grants or
	// identities; retry with Cascade.
	PlacementErrStillReferenced = 17
	// PlacementErrDuplicate means the natural key is already taken.
	PlacementErrDuplicate = 18
	// PlacementErrUnknownType means an unknown TargetType or Operation.
	PlacementErrUnknownType = 19
)

// placementErrorNames gives each placementd error code a stable short name,
// for logs and API responses.
var placementErrorNames = map[int]string{
	PlacementErrNotEncrypted:            "not_encrypted",
	PlacementErrMissingUserName:         "missing_user_name",
	PlacementErrUserNotAuthorized:       "user_not_authorized",
	PlacementErrAuthorizationDenied:     "authorization_denied",
	PlacementErrUserMappingExpired:      "user_mapping_expired",
	PlacementErrRequesterUnknown:        "requester_unknown",
	PlacementErrRequesterNotInstructor:  "requester_not_instructor",
	PlacementErrRequesterMappingExpired: "requester_mapping_expired",
	PlacementErrProjectNotAuthorized:    "project_not_authorized",
	PlacementErrDatabase:                "database",
	PlacementErrSchedd:                  "schedd",
	PlacementErrNotFound:                "not_found",
	PlacementErrVersionMismatch:         "version_mismatch",
	PlacementErrOwnedBySource:           "owned_by_other_source",
	PlacementErrInvalidArgument:         "invalid_argument",
	PlacementErrStillReferenced:         "still_referenced",
	PlacementErrDuplicate:               "duplicate",
	PlacementErrUnknownType:             "unknown_type",
}

// PlacementErrorName returns the short name of a placementd error code, or
// "" for a code the placementd does not define (a forwarded schedd error).
func PlacementErrorName(code int) string {
	return placementErrorNames[code]
}

// Name returns the short name of the error's code; see PlacementErrorName.
func (e *PlacementError) Name() string {
	return PlacementErrorName(e.Code)
}

// Target types for PlacementQuery.TargetType and PlacementOp.TargetType.
const (
	PlacementTargetIdentity      = "Identity"
	PlacementTargetAccount       = "Account"
	PlacementTargetProject       = "Project"
	PlacementTargetAuthorization = "Authorization"
	// PlacementTargetMapfileStatus is query-only.
	PlacementTargetMapfileStatus = "MapfileStatus"
	// PlacementTargetAll is Adopt-only: adopt every mapfile row.
	PlacementTargetAll = "All"
	// PlacementTargetModification is query-only: the audit log.
	PlacementTargetModification = "Modification"
)

// Operations for PlacementOp.Operation.
const (
	PlacementOpCreate = "Create"
	PlacementOpUpdate = "Update"
	PlacementOpDelete = "Delete"
	PlacementOpAdopt  = "Adopt"
)

// Owners an entity's Source can name.
const (
	// PlacementSourceMapfile rows are owned by PLACEMENTD_MAPFILE and
	// PLACEMENTD_AUTHORIZATIONS_MAPFILE. Edits refuse them; Adopt
	// transfers them.
	PlacementSourceMapfile = "mapfile"
	// PlacementSourceInternal rows are owned by the database and are
	// changed only by PLACEMENT_EDIT.
	PlacementSourceInternal = "internal"
)

// PlacementKeyAttr returns the attribute that holds a target type's natural
// key: Identity for identities, Name for every other type.
func PlacementKeyAttr(targetType string) string {
	if targetType == PlacementTargetIdentity {
		return "Identity"
	}
	return "Name"
}

// PlacementdAPIVersionAttr is the daemon-ad attribute that advertises which
// placementd commands the daemon serves.
const PlacementdAPIVersionAttr = "PlacementdApiVersion"

// PlacementdAPIVersionDirectory is the first API version that serves
// PLACEMENT_QUERY and PLACEMENT_EDIT.
const PlacementdAPIVersionDirectory = 2

// placementMaxOperations is the most operations one PLACEMENT_EDIT accepts.
const placementMaxOperations = 1000

// PlacementdAPIVersion reads PlacementdApiVersion from a placementd's daemon
// ad. A daemon that does not advertise it predates the attribute and is
// version 1.
func PlacementdAPIVersion(ad *classad.ClassAd) int {
	if ad == nil {
		return 1
	}
	v, ok := ad.EvaluateAttrInt(PlacementdAPIVersionAttr)
	if !ok || v < 1 {
		return 1
	}
	return int(v)
}

// QueryPlacementdAPIVersion asks the collector for the placementd's daemon ad
// and returns its PlacementdApiVersion. When several placementds advertise,
// the one whose MyAddress equals address wins; otherwise the first ad does.
// No ad at all is an error, not version 1, so a caller can tell "old daemon"
// from "could not look".
func QueryPlacementdAPIVersion(ctx context.Context, coll *Collector, address string) (int, error) {
	if coll == nil {
		return 0, fmt.Errorf("no collector to query for the placementd ad")
	}
	ads, _, err := coll.QueryAdsWithOptions(ctx, PlacementdAdType, "", &QueryOptions{
		Limit: -1,
		// The default projection would drop the attribute this asks for.
		Projection: []string{"MyAddress", "Name", PlacementdAPIVersionAttr},
	})
	if err != nil {
		return 0, fmt.Errorf("failed to query collector for placementd ads: %w", err)
	}
	if len(ads) == 0 {
		return 0, fmt.Errorf("no placementd ads found in collector")
	}
	chosen := ads[0]
	for _, ad := range ads {
		if a, ok := ad.EvaluateAttrString("MyAddress"); ok && a == address {
			chosen = ad
			break
		}
	}
	return PlacementdAPIVersion(chosen), nil
}

// PlacementQuery selects entities for Query. TargetType is required; the
// other fields narrow the result and may be combined.
type PlacementQuery struct {
	// TargetType is one of the PlacementTarget* constants other than
	// PlacementTargetAll.
	TargetType string
	// ID matches one entity by uuid.
	ID string
	// Key matches one entity by its natural key: the identity for an
	// Identity, the name for every other type. It is sent as the type's
	// key attribute (see PlacementKeyAttr).
	Key string
	// Requirements is a ClassAd expression evaluated against each result
	// ad; only matches are returned. It is sent as an expression, not a
	// string.
	Requirements string
	// Projection lists the attributes to return. The daemon always
	// includes Id. Empty means every attribute.
	Projection []string
	// Limit caps the number of results; zero or less means no cap.
	Limit int
	// EntityID restricts a Modification query to one entity's uuid.
	EntityID string
}

// PlacementEntityMeta is the bookkeeping every directory entity carries.
type PlacementEntityMeta struct {
	// ID is the entity's immutable uuid.
	ID string
	// Source is the entity's owner: PlacementSourceMapfile or
	// PlacementSourceInternal.
	Source string
	// Version changes on every change to the entity, including an
	// account's grants. Treat it as opaque: compare it, send it back as
	// ExpectedVersion, never do arithmetic on it.
	Version    int64
	CreatedAt  time.Time
	UpdatedAt  time.Time
	ModifiedBy string
	// ModificationID is the entity's latest audit-log entry; see
	// PlacementModification.
	ModificationID int64
}

// PlacementIdentity is an identity a web front end derives from an IdP
// login, mapped to exactly one account.
type PlacementIdentity struct {
	PlacementEntityMeta
	// Identity is the identity itself, the type's key.
	Identity string
	// AccountID is the uuid of the account; Account is its name.
	AccountID string
	Account   string
	// ExpiresAt is when the mapping stops being honored; the zero time
	// means never.
	ExpiresAt   time.Time
	Expired     bool
	DisplayName string
	Comment     string
	// The account's grants, denormalized for display.
	Authorizations []string
	Projects       []string
	DefaultProject string
	// LastTokenExpiration is the expiry of the newest token issued to this
	// identity; zero when none was.
	LastTokenExpiration time.Time
}

// PlacementAccount is an AP user that tokens are minted for. It owns the
// grants: the authorizations and projects every identity mapped to it may use.
type PlacementAccount struct {
	PlacementEntityMeta
	Name           string
	Authorizations []string
	Projects       []string
	DefaultProject string
	// Identities lists the names of the identities mapped to this account.
	Identities []string
}

// PlacementProject is a name an account may stamp into its token's project
// claim.
type PlacementProject struct {
	PlacementEntityMeta
	Name        string
	Description string
	// Accounts lists the names of the accounts granted this project.
	Accounts []string
}

// PlacementAuthorizationRecord is an authorization as a directory entity:
// the name a token's bounding set may carry, its display metadata, and
// whether it is offered for selection at login.
type PlacementAuthorizationRecord struct {
	PlacementEntityMeta
	Name        string
	Label       string
	Color       string
	Description string
	// Requestable marks authorizations offered as choices at login.
	// Granted authorizations that are not requestable are still minted
	// into tokens.
	Requestable bool
}

// PlacementMapfileProblem is one reason the last mapfile reconcile
// quarantined or reported a line.
type PlacementMapfileProblem struct {
	Kind    string
	File    string
	Line    int
	Key     string
	Message string
}

// PlacementMapfileStatus is the outcome of the placementd's most recent
// mapfile reconcile.
type PlacementMapfileStatus struct {
	// LoadTime is the last successful apply; LoadAttemptTime the last
	// attempt, successful or not.
	LoadTime        time.Time
	LoadAttemptTime time.Time
	// OK is true when the last attempt applied with no quarantines.
	OK bool
	// Quarantined counts keys whose lines were bad and so kept their
	// previous state.
	Quarantined int
	// Conflicts counts internal rows the mapfile reclaimed.
	Conflicts             int
	APIVersion            int
	UserMapfile           string
	AuthorizationsMapfile string
	Problems              []PlacementMapfileProblem
}

// PlacementObject is one PLACEMENT_QUERY result. Exactly one of the typed
// fields is set, matching Type; Ad is the raw reply for attributes the typed
// struct does not model.
type PlacementObject struct {
	// Type is the result's TargetType, from its MyType.
	Type          string
	Ad            *classad.ClassAd
	Identity      *PlacementIdentity
	Account       *PlacementAccount
	Project       *PlacementProject
	Authorization *PlacementAuthorizationRecord
	MapfileStatus *PlacementMapfileStatus
	Modification  *PlacementModification
}

// PlacementOp is one operation of a PLACEMENT_EDIT batch.
type PlacementOp struct {
	// Operation is one of the PlacementOp* constants.
	Operation string
	// TargetType is one of the PlacementTarget* constants;
	// PlacementTargetAll is for Adopt only.
	TargetType string
	// ID selects the entity by uuid. Not for Create.
	ID string
	// Key selects the entity by natural key when ID is empty, sent as
	// the type's key attribute (see PlacementKeyAttr). Not for Create.
	// To change the key, select by ID and put the new value in Fields.
	Key string
	// ExpectedVersion, when non-zero, makes the operation fail with
	// PlacementErrVersionMismatch unless the entity is at that version.
	ExpectedVersion int64
	// Cascade lets a Delete also remove the grants and identities that
	// reference the target.
	Cascade bool
	// Fields are the writable attributes, keyed by ClassAd attribute
	// name (Identity, Account, ExpiresAt, Name, Authorizations, ...).
	// Values may be string, bool, any integer type, time.Time (sent as
	// Unix seconds), []string (sent as a ClassAd list), or nil, which is
	// sent as the literal undefined and so clears the attribute. On
	// Update only the attributes present change, and a list replaces the
	// whole set.
	Fields map[string]any
}

// PlacementEditResult is the outcome of one operation of a batch.
type PlacementEditResult struct {
	// Index is the operation's position in the batch.
	Index int
	// ID and Version are the entity's values after the operation.
	ID      string
	Version int64
	// ErrorCode is non-zero when this operation failed; the batch was
	// then rolled back.
	ErrorCode   int
	ErrorString string
	// Warning is set on success when the change has a consequence the
	// caller should know about (a rename that the schedd does not follow,
	// an adopt the next reconcile will undo).
	Warning string
	Ad      *classad.ClassAd
}

// placementControlAttrs are the operation-ad attributes that are not
// entity fields. Fields may not set them, or a field could change what the
// operation does.
var placementControlAttrs = map[string]bool{
	"operation":       true,
	"targettype":      true,
	"id":              true,
	"expectedversion": true,
	"cascade":         true,
	"mytype":          true,
	"index":           true,
}

// Query runs PLACEMENT_QUERY and returns the matching entities. A query that
// matches nothing returns an empty slice, not an error.
func (p *Placementd) Query(ctx context.Context, q PlacementQuery) ([]PlacementObject, error) {
	ad, err := placementQueryAd(q)
	if err != nil {
		return nil, err
	}
	ads, err := p.streamQuery(ctx, PlacementQueryCommand, ad)
	if err != nil {
		return nil, err
	}
	out := make([]PlacementObject, 0, len(ads))
	for _, a := range ads {
		out = append(out, decodePlacementObject(a, q.TargetType))
	}
	return out, nil
}

// placementQueryAd builds the PLACEMENT_QUERY request ad.
func placementQueryAd(q PlacementQuery) (*classad.ClassAd, error) {
	if strings.TrimSpace(q.TargetType) == "" {
		return nil, &PlacementError{Code: PlacementErrInvalidArgument, Message: "placementd query: TargetType is required"}
	}
	ad := classad.New()
	ad.InsertAttrString("TargetType", q.TargetType)
	if q.ID != "" {
		ad.InsertAttrString("Id", q.ID)
	}
	if q.Key != "" {
		ad.InsertAttrString(PlacementKeyAttr(q.TargetType), q.Key)
	}
	if strings.TrimSpace(q.Requirements) != "" {
		expr, err := classad.ParseExpr(q.Requirements)
		if err != nil {
			return nil, &PlacementError{
				Code:    PlacementErrInvalidArgument,
				Message: fmt.Sprintf("placementd query: Requirements does not parse: %v", err),
			}
		}
		ad.InsertExpr("Requirements", expr)
	}
	if len(q.Projection) > 0 {
		ad.InsertAttrString("Projection", strings.Join(q.Projection, ","))
	}
	if q.Limit > 0 {
		ad.InsertAttr("Limit", int64(q.Limit))
	}
	if q.EntityID != "" {
		ad.InsertAttrString("EntityId", q.EntityID)
	}
	return ad, nil
}

// PlacementEditOptions qualifies a PLACEMENT_EDIT batch.
type PlacementEditOptions struct {
	// DryRun makes the daemon validate and report, then roll back.
	DryRun bool
	// OnBehalfOf names the person the caller is acting for, recorded in
	// the audit log next to the authenticated peer. The daemon records
	// it but does not authorize with it.
	OnBehalfOf string
	// Comment is recorded in the audit log with the batch.
	Comment string
}

// Edit runs a PLACEMENT_EDIT batch. The batch is atomic: either every
// operation applied or none did. With opts.DryRun the daemon validates and
// reports results, then rolls back.
//
// The results come back even when the batch failed, one per operation, so a
// caller can show which operation failed and why. In that case the error is a
// *PlacementError with the first failure's code.
//
// Arguments the daemon would refuse with PlacementErrInvalidArgument (an
// empty or oversized batch, a field that collides with an operation
// attribute, an unencodable value) are refused here with the same code
// before dialing.
func (p *Placementd) Edit(ctx context.Context, ops []PlacementOp, opts PlacementEditOptions) ([]PlacementEditResult, error) {
	header, opAds, err := placementEditAds(ops, opts)
	if err != nil {
		return nil, err
	}

	c, err := p.connect(ctx, PlacementEditCommand)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()

	stream := c.GetStream()
	req := message.NewMessageForStream(stream)
	// One message: the header, every operation, then end_of_message.
	for _, ad := range append([]*classad.ClassAd{header}, opAds...) {
		if err := req.PutClassAd(ctx, ad); err != nil {
			return nil, fmt.Errorf("failed to serialize edit request: %w", err)
		}
	}
	if err := req.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send edit request: %w", err)
	}

	reply := message.NewMessageFromStream(stream)
	var results []PlacementEditResult
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		ad, err := reply.GetClassAd(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read placementd reply: %w", err)
		}
		if myType, ok := ad.EvaluateAttrString("MyType"); ok && myType == summaryAdType {
			return results, placementSummaryError(ad)
		}
		results = append(results, decodePlacementEditResult(ad))
	}
}

// placementEditAds builds the header and operation ads for a batch.
func placementEditAds(ops []PlacementOp, opts PlacementEditOptions) (*classad.ClassAd, []*classad.ClassAd, error) {
	if len(ops) == 0 || len(ops) > placementMaxOperations {
		return nil, nil, &PlacementError{
			Code:    PlacementErrInvalidArgument,
			Message: fmt.Sprintf("placementd edit: a batch carries 1 to %d operations, not %d", placementMaxOperations, len(ops)),
		}
	}
	header := classad.New()
	header.InsertAttrString("MyType", "PlacementEdit")
	header.InsertAttr("NumOperations", int64(len(ops)))
	header.InsertAttrBool("DryRun", opts.DryRun)
	if opts.OnBehalfOf != "" {
		header.InsertAttrString("OnBehalfOf", opts.OnBehalfOf)
	}
	if opts.Comment != "" {
		header.InsertAttrString("Comment", opts.Comment)
	}

	opAds := make([]*classad.ClassAd, 0, len(ops))
	for i, op := range ops {
		ad, err := placementOpAd(op)
		if err != nil {
			return nil, nil, &PlacementError{
				Code:    PlacementErrInvalidArgument,
				Message: fmt.Sprintf("placementd edit: operation %d: %v", i, err),
			}
		}
		opAds = append(opAds, ad)
	}
	return header, opAds, nil
}

// placementOpAd encodes one operation.
func placementOpAd(op PlacementOp) (*classad.ClassAd, error) {
	if op.Operation == "" {
		return nil, fmt.Errorf("missing Operation")
	}
	if op.TargetType == "" {
		return nil, fmt.Errorf("missing TargetType")
	}
	ad := classad.New()
	ad.InsertAttrString("Operation", op.Operation)
	ad.InsertAttrString("TargetType", op.TargetType)

	keyAttr := PlacementKeyAttr(op.TargetType)
	if op.Operation == PlacementOpCreate && (op.ID != "" || op.Key != "") {
		return nil, fmt.Errorf("a Create takes no selector; put the %s in Fields", keyAttr)
	}
	if op.ID != "" {
		ad.InsertAttrString("Id", op.ID)
	}
	if op.ExpectedVersion != 0 {
		ad.InsertAttr("ExpectedVersion", op.ExpectedVersion)
	}
	if op.Cascade {
		if op.Operation != PlacementOpDelete {
			return nil, fmt.Errorf("only a Delete takes Cascade")
		}
		ad.InsertAttrBool("Cascade", true)
	}

	// The key attribute is both the selector and a writable field. One
	// ad holds it once: with an Id it is the new value, without one the
	// selector. So changing the key has to select by ID.
	rekeys := placementHasField(op.Fields, keyAttr)
	if op.Key != "" {
		if rekeys {
			return nil, fmt.Errorf("changing the %s selects by Id, not by %s", keyAttr, keyAttr)
		}
		ad.InsertAttrString(keyAttr, op.Key)
	}
	// An identity has no Name; the daemon refuses one.
	if op.TargetType == PlacementTargetIdentity {
		if placementHasField(op.Fields, "Name") {
			return nil, fmt.Errorf("an Identity is keyed by Identity, not Name")
		}
	}

	// Sorted so the wire bytes, and so any failure message, are stable.
	keys := make([]string, 0, len(op.Fields))
	for k := range op.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if placementControlAttrs[strings.ToLower(k)] {
			return nil, fmt.Errorf("%s is not an entity field", k)
		}
		if err := setPlacementField(ad, k, op.Fields[k]); err != nil {
			return nil, err
		}
	}
	return ad, nil
}

// placementHasField reports whether fields sets attr, compared
// case-insensitively as ClassAd attribute names are.
func placementHasField(fields map[string]any, attr string) bool {
	for k := range fields {
		if strings.EqualFold(k, attr) {
			return true
		}
	}
	return false
}

// setPlacementField encodes one field value.
func setPlacementField(ad *classad.ClassAd, name string, value any) error {
	switch v := value.(type) {
	case nil:
		// The literal undefined: clear the attribute.
		return ad.Set(name, nil)
	case time.Time:
		if v.IsZero() {
			return ad.Set(name, nil)
		}
		ad.InsertAttr(name, v.Unix())
		return nil
	case []string:
		if v == nil {
			// An empty list, not undefined: a nil slice still means
			// "replace the set with nothing".
			v = []string{}
		}
		return ad.Set(name, v)
	case string, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32:
		return ad.Set(name, v)
	default:
		return fmt.Errorf("field %s: unsupported value type %T", name, value)
	}
}

// placementSummaryError reads the Summary ad that ends an edit reply. Its
// ErrorCode is the batch's first failure; absent means it committed.
func placementSummaryError(ad *classad.ClassAd) error {
	code, hasCode := ad.EvaluateAttrInt("ErrorCode")
	msg, hasMsg := ad.EvaluateAttrString("ErrorString")
	if (!hasCode || code == 0) && !hasMsg {
		return nil
	}
	if msg == "" {
		msg = PlacementErrorName(int(code))
	}
	return &PlacementError{Code: int(code), Message: msg}
}

func decodePlacementEditResult(ad *classad.ClassAd) PlacementEditResult {
	r := PlacementEditResult{Ad: ad}
	if v, ok := ad.EvaluateAttrInt("Index"); ok {
		r.Index = int(v)
	}
	r.ID, _ = ad.EvaluateAttrString("Id")
	r.Version, _ = ad.EvaluateAttrInt("Version")
	if v, ok := ad.EvaluateAttrInt("ErrorCode"); ok {
		r.ErrorCode = int(v)
	}
	r.ErrorString, _ = ad.EvaluateAttrString("ErrorString")
	r.Warning, _ = ad.EvaluateAttrString("Warning")
	return r
}

// decodePlacementObject decodes one query result by its MyType, falling back
// to the query's TargetType when the ad carries none.
func decodePlacementObject(ad *classad.ClassAd, queried string) PlacementObject {
	typ := queried
	if myType, ok := ad.EvaluateAttrString("MyType"); ok {
		if t, found := strings.CutPrefix(myType, "Placement"); found && t != "" {
			typ = t
		}
	}
	obj := PlacementObject{Type: typ, Ad: ad}
	meta := decodePlacementMeta(ad)
	switch typ {
	case PlacementTargetIdentity:
		i := &PlacementIdentity{PlacementEntityMeta: meta}
		i.Identity, _ = ad.EvaluateAttrString("Identity")
		i.AccountID, _ = ad.EvaluateAttrString("AccountId")
		i.Account, _ = ad.EvaluateAttrString("Account")
		i.ExpiresAt = placementUnix(ad, "ExpiresAt")
		i.Expired, _ = ad.EvaluateAttrBool("Expired")
		i.DisplayName, _ = ad.EvaluateAttrString("DisplayName")
		i.Comment, _ = ad.EvaluateAttrString("Comment")
		i.Authorizations = placementStringList(ad, "Authorizations")
		i.Projects = placementStringList(ad, "Projects")
		i.DefaultProject, _ = ad.EvaluateAttrString("DefaultProject")
		i.LastTokenExpiration = placementUnix(ad, "LastTokenExpiration")
		obj.Identity = i
	case PlacementTargetAccount:
		a := &PlacementAccount{PlacementEntityMeta: meta}
		a.Name, _ = ad.EvaluateAttrString("Name")
		a.Authorizations = placementStringList(ad, "Authorizations")
		a.Projects = placementStringList(ad, "Projects")
		a.DefaultProject, _ = ad.EvaluateAttrString("DefaultProject")
		a.Identities = placementStringList(ad, "Identities")
		obj.Account = a
	case PlacementTargetProject:
		pr := &PlacementProject{PlacementEntityMeta: meta}
		pr.Name, _ = ad.EvaluateAttrString("Name")
		pr.Description, _ = ad.EvaluateAttrString("Description")
		pr.Accounts = placementStringList(ad, "Accounts")
		obj.Project = pr
	case PlacementTargetAuthorization:
		au := &PlacementAuthorizationRecord{PlacementEntityMeta: meta}
		au.Name, _ = ad.EvaluateAttrString("Name")
		au.Label, _ = ad.EvaluateAttrString("Label")
		au.Color, _ = ad.EvaluateAttrString("Color")
		au.Description, _ = ad.EvaluateAttrString("Description")
		au.Requestable = placementBool(ad, "Requestable")
		obj.Authorization = au
	case PlacementTargetMapfileStatus:
		obj.MapfileStatus = decodePlacementMapfileStatus(ad)
	case PlacementTargetModification:
		obj.Modification = decodePlacementModification(ad)
	}
	return obj
}

func decodePlacementMeta(ad *classad.ClassAd) PlacementEntityMeta {
	m := PlacementEntityMeta{}
	m.ID, _ = ad.EvaluateAttrString("Id")
	m.Source, _ = ad.EvaluateAttrString("Source")
	m.Version, _ = ad.EvaluateAttrInt("Version")
	m.CreatedAt = placementUnix(ad, "CreatedAt")
	m.UpdatedAt = placementUnix(ad, "UpdatedAt")
	m.ModifiedBy, _ = ad.EvaluateAttrString("ModifiedBy")
	m.ModificationID, _ = ad.EvaluateAttrInt("ModificationId")
	return m
}

func decodePlacementMapfileStatus(ad *classad.ClassAd) *PlacementMapfileStatus {
	s := &PlacementMapfileStatus{}
	s.LoadTime = placementUnix(ad, "PlacementdMapfileLoadTime")
	s.LoadAttemptTime = placementUnix(ad, "PlacementdMapfileLoadAttemptTime")
	s.OK = placementBool(ad, "PlacementdMapfileOK")
	if v, ok := ad.EvaluateAttrInt("PlacementdMapfileQuarantined"); ok {
		s.Quarantined = int(v)
	}
	if v, ok := ad.EvaluateAttrInt("PlacementdMapfileConflicts"); ok {
		s.Conflicts = int(v)
	}
	if _, ok := ad.Lookup(PlacementdAPIVersionAttr); ok {
		s.APIVersion = PlacementdAPIVersion(ad)
	}
	s.UserMapfile, _ = ad.EvaluateAttrString("UserMapfile")
	s.AuthorizationsMapfile, _ = ad.EvaluateAttrString("AuthorizationsMapfile")

	if list, err := ad.EvaluateAttr("Problems").ListValue(); err == nil {
		for _, v := range list {
			p, err := v.ClassAdValue()
			if err != nil || p == nil {
				continue
			}
			prob := PlacementMapfileProblem{}
			prob.Kind, _ = p.EvaluateAttrString("Kind")
			prob.File, _ = p.EvaluateAttrString("File")
			if line, ok := p.EvaluateAttrInt("Line"); ok {
				prob.Line = int(line)
			}
			prob.Key, _ = p.EvaluateAttrString("Key")
			prob.Message, _ = p.EvaluateAttrString("Message")
			s.Problems = append(s.Problems, prob)
		}
	}
	return s
}

// placementBool reads a boolean the daemon may also send as 0/1.
func placementBool(ad *classad.ClassAd, attr string) bool {
	if b, ok := ad.EvaluateAttrBool(attr); ok {
		return b
	}
	if i, ok := ad.EvaluateAttrInt(attr); ok {
		return i != 0
	}
	return false
}

// placementStringList reads a ClassAd list of strings. The v2 commands send
// lists, but a comma string is accepted too, as the v1 commands send them.
// Missing yields nil; an empty list yields an empty, non-nil slice.
func placementStringList(ad *classad.ClassAd, attr string) []string {
	v := ad.EvaluateAttr(attr)
	if v.IsList() {
		elems, err := v.ListValue()
		if err != nil {
			return nil
		}
		out := make([]string, 0, len(elems))
		for _, e := range elems {
			if s, err := e.StringValue(); err == nil {
				out = append(out, s)
			}
		}
		return out
	}
	return placementSplitList(ad, attr)
}
