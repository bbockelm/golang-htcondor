package htcondor

import (
	"context"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
)

// UserRecord is one of the schedd's per-user records, as returned by
// QUERY_USERREC_ADS. condor_qusers reads and writes the same records.
//
// The schedd creates a record the first time a user submits, so the set of
// records is "users this schedd has seen", not "users who exist". A user with
// no record has simply never submitted here; that is not a statement about
// their standing. See Enabled.
type UserRecord struct {
	// User is the fully-qualified user name, e.g. "alice@example.org".
	User string
	// Enabled reports whether the schedd will accept work from this user.
	//
	// It is a pointer because "the record does not say" is a distinct and
	// common answer from "false": the attribute is written when an admin
	// acts on the record (condor_qusers -enable/-disable), so an
	// auto-created record that nobody has touched may not carry it at all.
	// The schedd's own default for an unset value is enabled — its
	// JobQueueUserRec initializes `enabled=true`, and placementd reads the
	// attribute into a variable pre-set to 1 — so nil must be read as
	// "not disabled", never as a denial.
	Enabled *bool
	// DisableReason is the note an admin attached with
	// `condor_qusers -disable <user> -reason "..."`, when there is one.
	DisableReason string
	// Ad is the full record, for callers that want attributes beyond the
	// few lifted out above.
	Ad *classad.ClassAd
}

// IsDisabled reports whether the record affirmatively says this user is
// disabled. A record that does not mention Enabled returns false: absence of
// a statement is not a denial.
func (u *UserRecord) IsDisabled() bool {
	return u != nil && u.Enabled != nil && !*u.Enabled
}

// UserRecordQueryOptions narrows a user-record query.
type UserRecordQueryOptions struct {
	// Constraint is a ClassAd expression evaluated against each record,
	// e.g. `User == "alice@example.org"`.
	Constraint string
	// Projection limits the attributes returned. Empty returns everything.
	// Note that a projection which omits Enabled makes every record look
	// un-disabled, so include it whenever the answer matters.
	Projection []string
	// Limit caps the number of records returned. Zero or negative means
	// no limit.
	Limit int
}

// QueryUserRecords returns the schedd's user records matching opts.
//
// The command is registered at READ authorization on the schedd side, so this
// needs no special privilege beyond what any query requires — in contrast to
// ENABLE_USERREC / DISABLE_USERREC, which are ADMINISTRATOR. That split is
// what makes these records usable as a revocation signal by an unprivileged
// service: an admin disables a user, and everything else can only observe it.
func (s *Schedd) QueryUserRecords(ctx context.Context, opts *UserRecordQueryOptions) (records []UserRecord, err error) {
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, commands.QUERY_USERREC_ADS, "CLIENT", s.address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	htcondorClient, err := client.ConnectAndAuthenticate(ctx, s.address, secConfig)
	if err != nil {
		return nil, wrapScheddConnectError(s.address, err)
	}
	defer func() {
		if cerr := htcondorClient.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("failed to close connection: %w", cerr)
		}
	}()

	cedarStream := htcondorClient.GetStream()

	queryMsg := message.NewMessageForStream(cedarStream)
	if err := queryMsg.PutClassAd(ctx, createUserRecordQueryAd(opts)); err != nil {
		return nil, fmt.Errorf("failed to serialize user record query: %w", err)
	}
	if err := queryMsg.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send user record query: %w", err)
	}

	// The schedd streams matching ads and then a single ad with
	// MyType == "Summary" to mark the end. Unlike QUERY_JOB_ADS there is no
	// per-ad "more" flag; the summary ad is the only terminator.
	for {
		select {
		case <-ctx.Done():
			return records, ctx.Err()
		default:
		}

		responseMsg := message.NewMessageFromStream(cedarStream)
		ad, err := responseMsg.GetClassAd(ctx)
		if err != nil {
			return records, fmt.Errorf("failed to read user record ad: %w", err)
		}

		if myType, ok := ad.EvaluateAttrString("MyType"); ok && strings.EqualFold(myType, "Summary") {
			return records, nil
		}

		records = append(records, userRecordFromAd(ad))
	}
}

// GetUserRecord returns the record for one fully-qualified user, or nil when
// the schedd has no record of them.
//
// A nil record is NOT a denial. The schedd creates records lazily on first
// submit, so a user who has only ever queried — or who is new — has no record
// at all. Callers gating access must treat nil as "no information".
func (s *Schedd) GetUserRecord(ctx context.Context, user string) (*UserRecord, error) {
	if user == "" {
		return nil, fmt.Errorf("user is required")
	}
	records, err := s.QueryUserRecords(ctx, &UserRecordQueryOptions{
		Constraint: fmt.Sprintf("User == %s", classadQuoteString(user)),
		Projection: []string{"MyType", "User", "Name", "Enabled", "DisableReason"},
		Limit:      1,
	})
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, nil
	}
	return &records[0], nil
}

// createUserRecordQueryAd builds the request ad for QUERY_USERREC_ADS. The
// shape mirrors DCSchedd::makeUsersQueryAd on the C++ side.
func createUserRecordQueryAd(opts *UserRecordQueryOptions) *classad.ClassAd {
	ad := classad.New()
	// Ask only for Owner ads. The same command also serves Project ads,
	// and the schedd defaults to Owner when TargetType is absent, but
	// being explicit keeps the reply set stable if that default changes.
	_ = ad.Set("TargetType", "Owner")

	if opts == nil {
		return ad
	}
	if opts.Constraint != "" {
		expr, err := classad.ParseExpr(opts.Constraint)
		if err != nil {
			// Fail closed. A dropped constraint would silently widen the
			// query from one user to every user, and callers use this to
			// make access decisions.
			expr, _ = classad.ParseExpr("false")
		}
		ad.InsertExpr("Requirements", expr)
	}
	if len(opts.Projection) > 0 {
		_ = ad.Set("Projection", strings.Join(opts.Projection, ","))
	}
	if opts.Limit > 0 {
		_ = ad.Set("LimitResults", opts.Limit)
	}
	return ad
}

// userRecordFromAd lifts the attributes callers usually want out of a record.
func userRecordFromAd(ad *classad.ClassAd) UserRecord {
	rec := UserRecord{Ad: ad}
	if user, ok := ad.EvaluateAttrString("User"); ok {
		rec.User = user
	} else if name, ok := ad.EvaluateAttrString("Name"); ok {
		// Older records key on Name; qusers falls back the same way.
		rec.User = name
	}
	if enabled, ok := ad.EvaluateAttrBool("Enabled"); ok {
		rec.Enabled = &enabled
	} else if enabledInt, ok := ad.EvaluateAttrInt("Enabled"); ok {
		// The schedd writes Enabled with SetSecureAttributeInt, so it
		// arrives as 0/1 rather than a ClassAd boolean.
		b := enabledInt != 0
		rec.Enabled = &b
	}
	if reason, ok := ad.EvaluateAttrString("DisableReason"); ok {
		rec.DisableReason = reason
	}
	return rec
}

// classadQuoteString renders s as a ClassAd string literal for use inside a
// constraint expression.
func classadQuoteString(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
