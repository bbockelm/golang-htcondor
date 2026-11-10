package htcondor

import (
	"context"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
)

// Owned Capacity Units: persistent claims the schedd holds for a user.
//
// An OCU is negotiated like an idle job and then never given back. When
// the job running on it ends, the schedd keeps the claim and looks for
// another job of that user's to put on it. That is the whole mechanism:
// capacity that stays with its owner across job boundaries instead of
// returning to the pool between them.
//
// The three commands below are the schedd's management interface for
// them. They are not in cedar's command table, so their numbers are
// spelled out here against SCHED_VERS the way the other schedd commands
// this package reaches for are.
const (
	// cmdCreateOCU is CREATE_OCU_FOR_USERREC. Registered at WRITE and
	// then gated again on the schedd side: the caller must be a queue
	// super user or named in OCU_SUPER_USERS. WRITE alone is refused.
	cmdCreateOCU = commands.SCHED_VERS + 151
	// cmdRemoveOCU is REMOVE_OCU_FROM_USERREC, gated the same way.
	cmdRemoveOCU = commands.SCHED_VERS + 152
	// cmdQueryOCU is QUERY_OCU_FROM_USERREC, registered at READ with no
	// further gate -- and it answers with every OCU of every owner, not
	// just the caller's. There is no constraint in the protocol, so a
	// caller wanting one owner's claims filters the reply itself.
	cmdQueryOCU = commands.SCHED_VERS + 153
)

// OCU attribute names, from condor_attributes.h.
const (
	AttrOCUID    = "OCUId"
	AttrOCUName  = "OCUName"
	AttrOCUState = "OCUState"
	// AttrOCUWanted marks a job that may only run on an OCU claim. The
	// schedd refuses to put such a job on an ordinary match, so setting
	// it on a job that has no claim waiting leaves the job idle.
	AttrOCUWanted = "OCUWanted"
	// AttrOCUWilling marks a job that may borrow somebody else's idle
	// OCU claim, and be preempted when the owner wants it back.
	AttrOCUWilling = "OCUWilling"
)

// OCU is one persistent claim as the schedd reports it.
type OCU struct {
	// ID is the schedd-assigned identifier, unique within the schedd
	// and drawn from the same counter as cluster ids. It is what
	// RemoveOCU takes.
	ID int64
	// Name is the claim's label. The schedd names an unnamed claim
	// "OCU-<id>", so this is never empty in a reply.
	Name string
	// Owner is the user record the claim hangs off.
	Owner string
	// Project is the project whose jobs may use the claim, when the
	// claim was created with one.
	Project string
	// State is the schedd's one-letter status: 'I' while the claim is
	// held with nothing on it, 'R' while one of its jobs is running.
	// Empty means the claim has not been matched to a slot yet.
	State string
	// Ad is the full claim ad, for callers wanting attributes beyond
	// those lifted out above.
	Ad *classad.ClassAd
}

// Idle reports whether the claim is held with nothing running on it.
// That is the state a reservation wants its spare capacity in: the slot
// is already claimed, so a job of the owner's starts on it without
// waiting for a negotiation cycle.
func (o *OCU) Idle() bool { return o.State == "I" }

// Running reports whether a job is running on the claim.
func (o *OCU) Running() bool { return o.State == "R" }

// OCURequest describes a claim to create.
type OCURequest struct {
	// Owner is the user record the claim belongs to, as the schedd
	// spells it. The schedd looks the record up by this exact name and
	// refuses the request when it finds none, so a user who has never
	// submitted here cannot be given a claim -- see CreateOCU.
	Owner string
	// Project, when set, lets any job carrying it as its ProjectName
	// use the claim, not just jobs of Owner's.
	Project string
	// Name labels the claim. Empty lets the schedd name it.
	Name string
	// Submitter is the submitter name the claim is accounted under
	// while it waits to be matched. Empty leaves the claim out of the
	// submitter's idle count, which means the negotiator is never told
	// there is anything to match -- see CreateOCU.
	Submitter string
	// Request is the resource shape to claim, as a job would ask for
	// it: RequestCpus, RequestMemory, RequestDisk, RequestGpus, and a
	// Requirements expression if the claim should be narrowed to
	// particular machines.
	//
	// Nothing is defaulted. A claim with no RequestCpus asks for a slot
	// with no cpus.
	Request *classad.ClassAd
}

// CreateOCU asks the schedd for a persistent claim and returns it.
//
// Two conditions on the schedd side are worth knowing before calling,
// because neither is visible from here and both fail in ways that look
// like something else:
//
// The caller must be a queue super user or named in OCU_SUPER_USERS.
// This is checked after the command's own WRITE authorization, so a
// caller with WRITE gets a refusal from inside the handler rather than
// from the security layer.
//
// The owner must already have a user record. The schedd creates one on
// a user's first submission, so an owner who has never submitted to
// this schedd is refused -- not because they lack standing, but because
// there is nothing to hang the claim off yet.
func (s *Schedd) CreateOCU(ctx context.Context, req *OCURequest) (ocu *OCU, err error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.Owner == "" {
		return nil, fmt.Errorf("owner is required")
	}

	// The resource request is the base of the ad; the claim's identity
	// is written over it, so a Request that happens to carry an Owner
	// cannot contradict the one asked for.
	ad := classad.New()
	if req.Request != nil {
		for _, name := range req.Request.GetAttributes() {
			if expr, ok := req.Request.Lookup(name); ok && expr != nil {
				ad.InsertExpr(name, expr)
			}
		}
	}
	_ = ad.Set("Owner", req.Owner)
	if req.Project != "" {
		_ = ad.Set("ProjectName", req.Project)
	}
	if req.Name != "" {
		_ = ad.Set(AttrOCUName, req.Name)
	}
	if req.Submitter != "" {
		_ = ad.Set("Submitter", req.Submitter)
	}

	reply, err := s.ocuCommand(ctx, cmdCreateOCU, ad)
	if err != nil {
		return nil, err
	}
	if err := ocuResult(reply); err != nil {
		return nil, err
	}

	created := &OCU{Owner: req.Owner, Project: req.Project, Ad: reply}
	if id, ok := reply.EvaluateAttrInt(AttrOCUID); ok {
		created.ID = id
	} else {
		// Without an id the claim cannot be removed again, so a reply
		// that does not carry one is a failure even though the schedd
		// called it a success.
		return nil, fmt.Errorf("the schedd accepted the claim but did not say its %s, so it cannot be removed again", AttrOCUID)
	}
	if name, ok := reply.EvaluateAttrString(AttrOCUName); ok {
		created.Name = name
	}
	return created, nil
}

// RemoveOCU releases the claim with this id. The schedd gives the slot
// back to the pool; anything running on it is not preempted.
//
// Removing an id the schedd does not know is not an error: the reply
// says success either way, because the handler searches for the id and
// simply finds nothing. Callers wanting to know whether a claim existed
// read QueryOCUs first.
func (s *Schedd) RemoveOCU(ctx context.Context, id int64) error {
	ad := classad.New()
	_ = ad.Set(AttrOCUID, id)
	reply, err := s.ocuCommand(ctx, cmdRemoveOCU, ad)
	if err != nil {
		return err
	}
	return ocuResult(reply)
}

// QueryOCUs returns every persistent claim the schedd holds, for every
// owner. The protocol carries no constraint, so narrowing is the
// caller's job; OCUsFor does it by owner.
func (s *Schedd) QueryOCUs(ctx context.Context) (ocus []*OCU, err error) {
	secConfig, err := GetSecurityConfigOrDefault(ctx, s.cfg, cmdQueryOCU, "CLIENT", s.address)
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

	stream := htcondorClient.GetStream()
	out := message.NewMessageForStream(stream)
	if err := out.PutClassAd(ctx, classad.New()); err != nil {
		return nil, fmt.Errorf("failed to send the query: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send end of message: %w", err)
	}

	// The count and every ad arrive in one message, terminated once at
	// the end -- not one message per ad.
	in := message.NewMessageFromStream(stream)
	count, err := in.GetInt64(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read how many claims follow: %w", err)
	}
	if count < 0 {
		return nil, fmt.Errorf("the schedd said %d claims follow", count)
	}
	for i := int64(0); i < count; i++ {
		ad, err := in.GetClassAd(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to read claim %d of %d: %w", i+1, count, err)
		}
		ocus = append(ocus, ocuFromAd(ad))
	}
	return ocus, nil
}

// OCUsFor returns the claims held for one owner, or for one project
// when project is non-empty. An empty owner matches any.
func (s *Schedd) OCUsFor(ctx context.Context, owner, project string) ([]*OCU, error) {
	all, err := s.QueryOCUs(ctx)
	if err != nil {
		return nil, err
	}
	var mine []*OCU
	for _, o := range all {
		if owner != "" && o.Owner != owner {
			continue
		}
		if project != "" && o.Project != project {
			continue
		}
		mine = append(mine, o)
	}
	return mine, nil
}

// ocuCommand sends one request ad and reads the one reply ad that every
// OCU command but the query answers with.
func (s *Schedd) ocuCommand(ctx context.Context, cmd int, request *classad.ClassAd) (reply *classad.ClassAd, err error) {
	secConfig, err := GetSecurityConfigOrDefault(ctx, s.cfg, cmd, "CLIENT", s.address)
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

	stream := htcondorClient.GetStream()
	out := message.NewMessageForStream(stream)
	if err := out.PutClassAd(ctx, request); err != nil {
		return nil, fmt.Errorf("failed to send the request: %w", err)
	}
	if err := out.FinishMessage(ctx); err != nil {
		return nil, fmt.Errorf("failed to send end of message: %w", err)
	}

	in := message.NewMessageFromStream(stream)
	reply, err = in.GetClassAd(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to read the reply: %w", err)
	}
	return reply, nil
}

// ocuResult turns the schedd's Result/ErrorString pair into an error.
//
// A reply with no Result at all is treated as a failure rather than as
// a success: the handler sets it on every path it takes, so its absence
// means the reply is not one of those paths.
func ocuResult(reply *classad.ClassAd) error {
	if reply == nil {
		return fmt.Errorf("the schedd sent no reply")
	}
	result, ok := reply.EvaluateAttrInt("Result")
	if !ok {
		return fmt.Errorf("the schedd's reply carries no Result")
	}
	if result == 0 {
		return nil
	}
	if msg, ok := reply.EvaluateAttrString("ErrorString"); ok && msg != "" {
		return fmt.Errorf("the schedd refused the request: %s", msg)
	}
	return fmt.Errorf("the schedd refused the request (Result %d)", result)
}

func ocuFromAd(ad *classad.ClassAd) *OCU {
	o := &OCU{Ad: ad}
	if ad == nil {
		return o
	}
	if v, ok := ad.EvaluateAttrInt(AttrOCUID); ok {
		o.ID = v
	}
	if v, ok := ad.EvaluateAttrString(AttrOCUName); ok {
		o.Name = v
	}
	if v, ok := ad.EvaluateAttrString("Owner"); ok {
		o.Owner = v
	}
	if v, ok := ad.EvaluateAttrString("ProjectName"); ok {
		o.Project = v
	}
	if v, ok := ad.EvaluateAttrString(AttrOCUState); ok {
		o.State = v
	}
	return o
}
