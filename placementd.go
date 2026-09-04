package htcondor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
)

// Command codes for the placement daemon (condor_placementd), from
// condor_commands.h. They are defined here rather than in cedar's commands
// package because the placementd is new enough that cedar has not enumerated
// them; the values are the stable wire numbers.
const (
	// PlacementUserLogin requests an IDToken for a foreign user identity.
	PlacementUserLogin = commands.SCHED_VERS + 155
	// PlacementQueryUsers lists the users the placementd knows about.
	PlacementQueryUsers = commands.SCHED_VERS + 156
	// PlacementQueryTokens lists the tokens the placementd has issued.
	PlacementQueryTokens = commands.SCHED_VERS + 157
	// PlacementQueryAuthorizations lists the authorizations the placementd
	// can grant, optionally narrowed to those a single user may request.
	PlacementQueryAuthorizations = commands.SCHED_VERS + 158
)

// Error codes the placementd assigns to its own failures (placementd.cpp).
// The daemon also forwards CondorError codes from the schedd verbatim, so a
// code outside this set is a schedd-side error, not one of these.
const (
	// PlacementErrNotEncrypted means the request arrived unencrypted. The
	// daemon refuses to mint a token over a channel that would expose it.
	PlacementErrNotEncrypted = 1
	// PlacementErrMissingUserName means the request carried no UserName.
	PlacementErrMissingUserName = 2
	// PlacementErrUserNotAuthorized means the user is absent from the
	// placementd's map file.
	PlacementErrUserNotAuthorized = 3
	// PlacementErrAuthorizationDenied means the user asked for an
	// authorization their map-file entry does not grant.
	PlacementErrAuthorizationDenied = 4
	// PlacementErrUserMappingExpired means the user's map-file entry has an
	// expiration in the past.
	PlacementErrUserMappingExpired = 6
	// PlacementErrRequesterUnknown means a login made on another user's
	// behalf named a requester absent from the map file.
	PlacementErrRequesterUnknown = 7
	// PlacementErrRequesterNotInstructor means the requester exists but
	// lacks the INSTRUCTOR authorization needed to act for someone else.
	PlacementErrRequesterNotInstructor = 8
	// PlacementErrRequesterMappingExpired means the requester's own
	// map-file entry has expired.
	PlacementErrRequesterMappingExpired = 9
	// PlacementErrProjectNotAuthorized means the user's map-file entry does
	// not list the requested project.
	PlacementErrProjectNotAuthorized = 10
	// PlacementErrDatabase means the placementd could not record the issued
	// token in its sqlite database. No token is returned in that case even
	// though one was minted.
	PlacementErrDatabase = 11
	// PlacementErrSchedd means the schedd leg of a login failed: the schedd
	// could not be located or queried, or the user or project record there
	// exists but is disabled.
	PlacementErrSchedd = 12
)

// PlacementError is an error the placementd reported in its reply ad, carrying
// the daemon's own ErrorCode/ErrorString rather than a transport failure.
// Callers that need to distinguish, say, "this user may not have that
// authorization" from "the schedd is down" should errors.As to this type and
// switch on Code against the PlacementErr* constants.
type PlacementError struct {
	Code    int
	Message string
}

func (e *PlacementError) Error() string {
	return fmt.Sprintf("placementd error %d: %s", e.Code, e.Message)
}

// PlacementLoginRequest asks the placementd to mint an IDToken.
type PlacementLoginRequest struct {
	// UserName is the foreign identity to log in -- the left-hand column of
	// the placementd map file, not the local AP account. Required.
	UserName string
	// Authorizations narrows the token's bounding set to these
	// authorizations. Every entry must be one the user's map-file line
	// grants, or the login is refused entirely (the daemon does not silently
	// drop the ones it cannot grant). Empty means "everything this user is
	// entitled to".
	Authorizations []string
	// Project ties the token, and so the jobs submitted with it, to an AP
	// project. It must appear in the user's map-file project list. Empty
	// means the token carries no project claim.
	Project string
	// Requester is the foreign identity of whoever is asking, when that is
	// not the user being logged in -- an instructor minting a token for a
	// student, say. The requester must itself be mapped and hold the
	// INSTRUCTOR authorization. Empty means the user is requesting for
	// themselves.
	Requester string
}

// PlacementLoginResult is a successful login.
type PlacementLoginResult struct {
	// Token is the signed IDToken. Treat it as a secret: it is a bearer
	// credential for the AP identity it names.
	Token string
	// Ad is the daemon's full reply ad, so callers can read attributes this
	// struct does not model yet.
	Ad *classad.ClassAd
}

// PlacementUser is one row of the placementd's user view: the map-file entry
// for a foreign identity, merged with the newest unexpired token issued to it.
type PlacementUser struct {
	// UserName is the foreign identity.
	UserName string
	// APUserID is the local AP account the identity maps to (the token's
	// subject).
	APUserID string
	// TokenExpiration is when the newest unexpired token for this user runs
	// out; the zero time means no live token.
	TokenExpiration time.Time
	// MappingExpiration is when the map-file entry itself stops being
	// honored; the zero time means it never does.
	MappingExpiration time.Time
	// Projects are the AP projects this identity may bind a token to.
	Projects []string
	// Authorizations are the authorizations the map file grants.
	Authorizations []string
	// Authorized reports whether the identity is still in the map file. A
	// user with live tokens but no map-file entry comes back with
	// Authorized false: their tokens work until they expire, but they can no
	// longer log in.
	Authorized bool
}

// PlacementToken is one issued token as recorded in the placementd database.
// The token itself is not stored, only its identity and claims.
type PlacementToken struct {
	// Requester is the foreign identity that asked for the token, which
	// differs from UserName only for instructor-issued tokens.
	Requester string
	// UserName is the foreign identity the token was issued for.
	UserName string
	// APUserID is the local AP account named in the token's subject.
	APUserID string
	// Authorizations is the token's bounding set.
	Authorizations []string
	// TokenID is the token's jti claim, the handle for talking about one
	// specific token.
	TokenID string
	// Expiration is the token's exp claim.
	Expiration time.Time
	// Project is the project claim, empty when the token carries none.
	Project string
}

// PlacementTokenQuery narrows QueryTokens. A zero query returns every token
// the daemon has ever issued, expired ones included.
type PlacementTokenQuery struct {
	// UserName restricts the result to tokens issued for one foreign
	// identity.
	UserName string
	// TokenID restricts the result to the single token with this jti. It
	// takes precedence over the other two fields: the daemon applies it
	// alone.
	TokenID string
	// ValidOnly drops tokens that have already expired.
	ValidOnly bool
}

// PlacementAuthorization is one authorization the placementd can grant, with
// the display metadata its authorizations map file carries so a UI can render
// the same labels and colors the reference portal does.
type PlacementAuthorization struct {
	// Name is the authorization as it appears in a token's bounding set.
	Name string
	// Label is the human-readable name to show instead of Name.
	Label string
	// Color is the operator's suggested display color for the badge. It is
	// whatever the map file says -- a CSS color name, a hex triplet, or a
	// token meaningful only to a particular UI -- so treat it as a hint and
	// have a fallback.
	Color string
	// Description is a sentence explaining what the authorization permits.
	Description string
}

// PlacementdClient is the placementd operations, as an interface so callers
// (notably the web API) can substitute a fake in tests.
type PlacementdClient interface {
	// Login mints an IDToken for a foreign identity.
	Login(ctx context.Context, req PlacementLoginRequest) (*PlacementLoginResult, error)
	// QueryUsers lists known users; an empty userName lists all of them.
	QueryUsers(ctx context.Context, userName string) ([]PlacementUser, error)
	// QueryTokens lists issued tokens.
	QueryTokens(ctx context.Context, query PlacementTokenQuery) ([]PlacementToken, error)
	// QueryAuthorizations lists grantable authorizations; a non-empty
	// userName narrows the list to what that user may request.
	QueryAuthorizations(ctx context.Context, userName string) ([]PlacementAuthorization, error)
}

// Placementd is a CEDAR client for condor_placementd.
//
// Every command the daemon registers requires ADMINISTRATOR authorization and
// forced authentication, and the login command additionally refuses to run on
// an unencrypted channel (it would otherwise hand a bearer token to anyone on
// the path). This client therefore demands authentication and encryption on
// every connection rather than letting configuration weaken them.
type Placementd struct {
	address string
}

// Compile-time check that Placementd satisfies the interface.
var _ PlacementdClient = (*Placementd)(nil)

// NewPlacementd returns a client for the placementd at address, a sinful
// string. Use Collector.LocateDaemon with DaemonPlacementd to find one.
func NewPlacementd(address string) *Placementd {
	return &Placementd{address: address}
}

// Address returns the sinful string this client talks to.
func (p *Placementd) Address() string { return p.address }

// summaryAdType is the MyType the placementd puts on the trailing ad of a
// query response. The ad carries no payload of its own beyond an optional
// ErrorCode/ErrorString pair; it exists to terminate the stream.
const summaryAdType = "Summary"

// connect dials the placementd and authenticates for one command.
func (p *Placementd) connect(ctx context.Context, cmd int) (*client.HTCondorClient, error) {
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, cmd, "CLIENT", p.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}
	// Not negotiable: see the type comment.
	secConfig.Authentication = security.SecurityRequired
	secConfig.Encryption = security.SecurityRequired

	c, err := client.ConnectAndAuthenticate(ctx, p.address, secConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to placementd at %s: %w", p.address, err)
	}
	return c, nil
}

// sendRequest writes the command ad and returns the reply message to read
// from. The caller closes the client.
func sendPlacementRequest(ctx context.Context, c *client.HTCondorClient, ad *classad.ClassAd) (*message.Message, error) {
	stream := c.GetStream()
	req := message.NewMessageForStream(stream)
	if err := req.PutClassAd(ctx, ad); err != nil {
		return nil, fmt.Errorf("failed to serialize request: %w", err)
	}
	if err := req.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	return message.NewMessageFromStream(stream), nil
}

// Login mints an IDToken for a foreign identity. See PlacementLoginRequest for
// what the daemon does with each field.
//
// A login has a side effect beyond the token: the placementd creates the AP
// user record -- and the project record, when the request names a project --
// in the schedd if they do not already exist. A login against a disabled user
// or project fails with PlacementErrSchedd rather than re-enabling it.
func (p *Placementd) Login(ctx context.Context, req PlacementLoginRequest) (*PlacementLoginResult, error) {
	if strings.TrimSpace(req.UserName) == "" {
		return nil, fmt.Errorf("placementd login: UserName is required")
	}

	c, err := p.connect(ctx, PlacementUserLogin)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()

	ad := classad.New()
	if err := ad.Set("UserName", req.UserName); err != nil {
		return nil, fmt.Errorf("failed to set UserName: %w", err)
	}
	// The daemon always reads Authorizations; an empty value means "the
	// user's full set", which is what an empty slice should mean here too.
	if err := ad.Set("Authorizations", strings.Join(req.Authorizations, ",")); err != nil {
		return nil, fmt.Errorf("failed to set Authorizations: %w", err)
	}
	if req.Project != "" {
		if err := ad.Set("Project", req.Project); err != nil {
			return nil, fmt.Errorf("failed to set Project: %w", err)
		}
	}
	if req.Requester != "" {
		if err := ad.Set("Requester", req.Requester); err != nil {
			return nil, fmt.Errorf("failed to set Requester: %w", err)
		}
	}

	reply, err := sendPlacementRequest(ctx, c, ad)
	if err != nil {
		return nil, err
	}

	resultAd, err := reply.GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read placementd reply: %w", err)
	}
	if err := placementAdError(resultAd); err != nil {
		return nil, err
	}

	token, ok := resultAd.EvaluateAttrString("Token")
	if !ok || token == "" {
		// A reply with neither an error nor a token means the daemon
		// changed its contract; surfacing it as an error beats handing
		// back an empty credential.
		return nil, fmt.Errorf("placementd returned no token and no error")
	}
	return &PlacementLoginResult{Token: token, Ad: resultAd}, nil
}

// QueryUsers lists the users the placementd knows about: everyone in its map
// file, plus anyone holding an unexpired token even if their mapping is gone
// (those come back with Authorized false). An empty userName lists all of
// them; a userName that is neither mapped nor holds a live token yields an
// empty result, not an error.
func (p *Placementd) QueryUsers(ctx context.Context, userName string) ([]PlacementUser, error) {
	ad := classad.New()
	if userName != "" {
		if err := ad.Set("UserName", userName); err != nil {
			return nil, fmt.Errorf("failed to set UserName: %w", err)
		}
	}

	ads, err := p.streamQuery(ctx, PlacementQueryUsers, ad)
	if err != nil {
		return nil, err
	}

	users := make([]PlacementUser, 0, len(ads))
	for _, a := range ads {
		u := PlacementUser{}
		u.UserName, _ = a.EvaluateAttrString("UserName")
		u.APUserID, _ = a.EvaluateAttrString("ApUserId")
		u.TokenExpiration = placementUnix(a, "TokenExpiration")
		// The daemon spells this attribute "MappingExpration" (sic). Read
		// the corrected spelling too so we keep working if that is fixed.
		u.MappingExpiration = placementUnix(a, "MappingExpration")
		if u.MappingExpiration.IsZero() {
			u.MappingExpiration = placementUnix(a, "MappingExpiration")
		}
		u.Projects = placementSplitList(a, "Projects")
		u.Authorizations = placementSplitList(a, "Authorizations")
		u.Authorized, _ = a.EvaluateAttrBool("Authorized")
		users = append(users, u)
	}
	return users, nil
}

// QueryTokens lists tokens the placementd has issued. Tokens are never removed
// from its database, so an unfiltered query returns expired ones too; set
// PlacementTokenQuery.ValidOnly to see only live tokens.
func (p *Placementd) QueryTokens(ctx context.Context, query PlacementTokenQuery) ([]PlacementToken, error) {
	ad := classad.New()
	if query.TokenID != "" {
		if err := ad.Set("TokenId", query.TokenID); err != nil {
			return nil, fmt.Errorf("failed to set TokenId: %w", err)
		}
	}
	if query.UserName != "" {
		if err := ad.Set("UserName", query.UserName); err != nil {
			return nil, fmt.Errorf("failed to set UserName: %w", err)
		}
	}
	if err := ad.Set("ValidOnly", query.ValidOnly); err != nil {
		return nil, fmt.Errorf("failed to set ValidOnly: %w", err)
	}

	ads, err := p.streamQuery(ctx, PlacementQueryTokens, ad)
	if err != nil {
		return nil, err
	}

	tokens := make([]PlacementToken, 0, len(ads))
	for _, a := range ads {
		t := PlacementToken{}
		t.Requester, _ = a.EvaluateAttrString("Requester")
		t.UserName, _ = a.EvaluateAttrString("UserName")
		t.APUserID, _ = a.EvaluateAttrString("ApUserId")
		t.Authorizations = placementSplitList(a, "Authorizations")
		t.TokenID, _ = a.EvaluateAttrString("TokenId")
		t.Expiration = placementUnix(a, "TokenExpiration")
		t.Project, _ = a.EvaluateAttrString("Project")
		tokens = append(tokens, t)
	}
	return tokens, nil
}

// QueryAuthorizations lists the authorizations the placementd can grant, with
// the display metadata from its authorizations map file. An empty userName
// lists every defined authorization; a non-empty one narrows the list to those
// that user may request, and fails with PlacementErrUserNotAuthorized if the
// user is not mapped.
func (p *Placementd) QueryAuthorizations(ctx context.Context, userName string) ([]PlacementAuthorization, error) {
	ad := classad.New()
	if userName != "" {
		if err := ad.Set("UserName", userName); err != nil {
			return nil, fmt.Errorf("failed to set UserName: %w", err)
		}
	}

	ads, err := p.streamQuery(ctx, PlacementQueryAuthorizations, ad)
	if err != nil {
		return nil, err
	}

	authz := make([]PlacementAuthorization, 0, len(ads))
	for _, a := range ads {
		one := PlacementAuthorization{}
		one.Name, _ = a.EvaluateAttrString("Name")
		one.Label, _ = a.EvaluateAttrString("Label")
		one.Color, _ = a.EvaluateAttrString("Color")
		one.Description, _ = a.EvaluateAttrString("Description")
		authz = append(authz, one)
	}
	return authz, nil
}

// streamQuery runs one of the three query commands and returns the result ads,
// stopping at the trailing Summary ad.
//
// The daemon writes every result ad and the Summary ad into a SINGLE CEDAR
// message -- it calls end_of_message only once, after the Summary -- so all of
// them are read from one Message rather than one Message per ad the way the
// schedd's query commands work.
func (p *Placementd) streamQuery(ctx context.Context, cmd int, requestAd *classad.ClassAd) ([]*classad.ClassAd, error) {
	c, err := p.connect(ctx, cmd)
	if err != nil {
		return nil, err
	}
	defer func() { _ = c.Close() }()

	reply, err := sendPlacementRequest(ctx, c, requestAd)
	if err != nil {
		return nil, err
	}

	var ads []*classad.ClassAd
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
			// The Summary ad ends the stream, and carries the error for
			// failures the daemon only detects after it has started
			// replying.
			if err := placementAdError(ad); err != nil {
				return nil, err
			}
			return ads, nil
		}
		ads = append(ads, ad)
	}
}

// placementAdError converts a reply ad's ErrorString/ErrorCode into a
// PlacementError, or returns nil when the ad reports no error. The daemon
// signals failure by the presence of ErrorString, so an ad with an ErrorCode
// but no ErrorString is a success.
func placementAdError(ad *classad.ClassAd) error {
	msg, ok := ad.EvaluateAttrString("ErrorString")
	if !ok {
		return nil
	}
	code := 0
	if c, ok := ad.EvaluateAttrInt("ErrorCode"); ok {
		code = int(c)
	}
	return &PlacementError{Code: code, Message: msg}
}

// placementUnix reads a Unix-seconds attribute as a time. A missing or
// non-positive value -- which is how the daemon spells "no expiration" and
// "no live token" alike -- yields the zero time.
func placementUnix(ad *classad.ClassAd, attr string) time.Time {
	v, ok := ad.EvaluateAttrInt(attr)
	if !ok || v <= 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

// placementSplitList reads a delimited list attribute into a slice, using
// HTCondor's default token delimiters (comma and whitespace) so it accepts
// both the comma-joined lists the daemon writes to its database and the
// whitespace-separated ones an operator may write in a map file. A missing or
// empty attribute yields a nil slice.
func placementSplitList(ad *classad.ClassAd, attr string) []string {
	raw, ok := ad.EvaluateAttrString(attr)
	if !ok {
		return nil
	}
	var out []string
	for _, field := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	}) {
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}
