package htcondor

import (
	"context"
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/stream"
	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/qmgmt"
)

// SetAttributeFlags controls behavior when setting job attributes. It aliases
// the shared codec type in the qmgmt package.
type SetAttributeFlags = qmgmt.SetAttributeFlags

const (
	// SetAttributeNoAck indicates not to wait for acknowledgment when setting
	// attributes (SetAttribute_NoAck, bit 1<<1 in condor_qmgr.h).
	SetAttributeNoAck SetAttributeFlags = qmgmt.SetNoAck
)

// QMGMT Protocol Commands. The canonical definitions now live in the qmgmt
// codec package (shared with the server); these names are kept for backward
// compatibility and match HTCondor's C++ naming convention.
//
//nolint:revive // Protocol constants match HTCondor C++ naming convention
const (
	CONDOR_NewCluster               = qmgmt.OpNewCluster
	CONDOR_NewProc                  = qmgmt.OpNewProc
	CONDOR_DestroyCluster           = qmgmt.OpDestroyCluster
	CONDOR_SetAttribute             = qmgmt.OpSetAttribute
	CONDOR_SetAttribute2            = qmgmt.OpSetAttribute2
	CONDOR_BeginTransaction         = qmgmt.OpBeginTransaction
	CONDOR_CommitTransactionNoFlags = qmgmt.OpCommitTransactionNoFlags
	CONDOR_CommitTransaction        = qmgmt.OpCommitTransaction
	CONDOR_AbortTransaction         = qmgmt.OpAbortTransaction
	CONDOR_SetEffectiveOwner        = qmgmt.OpSetEffectiveOwner
	CONDOR_GetCapabilities          = qmgmt.OpGetCapabilities
	CONDOR_CloseSocket              = qmgmt.OpCloseSocket
	QMGMT_WRITE_CMD                 = qmgmt.WriteCmd
)

// QmgmtConnection represents an active connection to the schedd for queue management operations
// Implements HTCondor's QMGMT (Queue Management) protocol for job submission
//
// Protocol Flow:
//  1. TCP connection to schedd
//  2. DC_AUTHENTICATE handshake
//  3. QMGMT_WRITE_CMD (1112) to enter queue management mode
//  4. GetCapabilities (10036) to query schedd capabilities
//  5. BeginTransaction (10023)
//  6. NewCluster (10002) → cluster ID
//  7. NewProc (10003) → proc ID
//  8. SetAttribute (10006) for each attribute
//  9. CommitTransaction (10007)
//  10. CloseSocket (10028)
type QmgmtConnection struct {
	address            string
	htcondorClient     *client.HTCondorClient
	stream             *stream.Stream
	authenticatedUser  string // User from authentication negotiation
	inTransaction      bool
	hasJobsets         bool //nolint:unused // Will be used when implementing jobsets
	allowsLateMat      bool //nolint:unused // Will be used when implementing late materialization
	lateMaterializeVer int  //nolint:unused // Will be used when implementing late materialization
}

// NewQmgmtConnection establishes a queue management connection to the schedd
// Uses FS authentication from cedar package
// address can be a hostname:port or a sinful string like "<IP:PORT?addrs=...>"
func NewQmgmtConnection(ctx context.Context, address string) (*QmgmtConnection, error) {
	return newQmgmtConnection(ctx, nil, address)
}

// newQmgmtConnection is NewQmgmtConnection reading the security settings from
// cfg (nil: the process-wide default), so a Schedd's queue connections use
// that Schedd's configuration.
func newQmgmtConnection(ctx context.Context, cfg *config.Config, address string) (*QmgmtConnection, error) {
	// Get SecurityConfig from context, HTCondor config, or defaults
	secConfig, err := GetSecurityConfigOrDefault(ctx, cfg, QMGMT_WRITE_CMD, "CLIENT", address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Establish connection and authenticate
	// ConnectAndAuthenticate now provides access to negotiation details via GetSecurityNegotiation()
	htcondorClient, err := client.ConnectAndAuthenticate(ctx, address, secConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect and authenticate to schedd at %s: %w", address, err)
	}

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// Get security negotiation result
	negotiation := htcondorClient.GetSecurityNegotiation()
	if negotiation == nil {
		_ = htcondorClient.Close()
		return nil, fmt.Errorf("no security negotiation performed")
	}

	// Verify authentication succeeded (accept any of the configured auth methods)
	authMethodValid := false
	for _, method := range secConfig.AuthMethods {
		if negotiation.NegotiatedAuth == method {
			authMethodValid = true
			break
		}
	}
	if !authMethodValid {
		_ = htcondorClient.Close()
		return nil, fmt.Errorf("authentication failed: expected one of %v, got %s", secConfig.AuthMethods, negotiation.NegotiatedAuth)
	}

	// Check return code - should be AUTHORIZED
	// The post-auth response should contain ReturnCode
	// If DENIED, the connection is not authorized for QMGMT operations

	// Stream should now be ready for QMGMT commands
	// Mark stream as authenticated
	cedarStream.SetAuthenticated(true)

	// Query capabilities - this is required before other QMGMT operations
	// Send CONDOR_GetCapabilities (10036) command
	capMsg := message.NewMessageForStream(cedarStream)
	if err := capMsg.PutInt(ctx, CONDOR_GetCapabilities); err != nil {
		_ = htcondorClient.Close()
		return nil, fmt.Errorf("failed to send GetCapabilities command: %w", err)
	}
	if err := capMsg.PutInt(ctx, 0); err != nil { // flags = 0
		_ = htcondorClient.Close()
		return nil, fmt.Errorf("failed to send GetCapabilities flags: %w", err)
	}
	if err := capMsg.FinishMessage(ctx); err != nil {
		_ = htcondorClient.Close()
		return nil, fmt.Errorf("failed to finish GetCapabilities message: %w", err)
	}

	// Read capabilities response
	// Note: GetCapabilities is special - it returns a ClassAd directly, no status code
	capResponse := message.NewMessageFromStream(cedarStream)
	capabilities, err := capResponse.GetClassAd(ctx)
	if err != nil {
		_ = htcondorClient.Close()
		return nil, fmt.Errorf("failed to read capabilities ClassAd: %w", err)
	}

	// TODO: Parse capabilities to set hasJobsets, allowsLateMat, lateMaterializeVer
	_ = capabilities

	q := &QmgmtConnection{
		address:           address,
		htcondorClient:    htcondorClient,
		stream:            cedarStream,
		authenticatedUser: negotiation.User, // Store authenticated user
		inTransaction:     true,             // GetCapabilities implicitly starts a transaction
	}

	// Success!
	return q, nil
}

// Close disconnects from the schedd queue
func (q *QmgmtConnection) Close() error {
	if q == nil {
		return nil
	}

	// Send CONDOR_CloseSocket (10028) command
	if q.stream != nil {
		msg := message.NewMessageForStream(q.stream)
		ctx := context.Background()
		if err := msg.PutInt(ctx, CONDOR_CloseSocket); err != nil {
			// Log but don't fail on close errors
			fmt.Printf("Warning: failed to send CloseSocket command: %v\n", err)
		} else {
			_ = msg.FinishMessage(ctx)
		}
	}

	if q.htcondorClient != nil {
		return q.htcondorClient.Close()
	}
	return nil
}

// BeginTransaction starts a queue management transaction
func (q *QmgmtConnection) BeginTransaction(ctx context.Context) error {
	if q.inTransaction {
		return fmt.Errorf("transaction already in progress")
	}

	// Send CONDOR_BeginTransaction (10023) command
	msg := message.NewMessageForStream(q.stream)
	if err := msg.PutInt(ctx, CONDOR_BeginTransaction); err != nil {
		return fmt.Errorf("failed to send BeginTransaction command: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish BeginTransaction message: %w", err)
	}

	// Receive response
	responseMsg := message.NewMessageFromStream(q.stream)
	rval, err := responseMsg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive BeginTransaction response: %w", err)
	}

	if rval < 0 {
		// Read error code
		errCode, err := responseMsg.GetInt(ctx)
		if err != nil {
			return fmt.Errorf("BeginTransaction failed but could not read error code: %w", err)
		}
		return fmt.Errorf("BeginTransaction failed with error code %d", errCode)
	}

	q.inTransaction = true
	return nil
}

// CommitTransaction commits a queue management transaction
func (q *QmgmtConnection) CommitTransaction(ctx context.Context) error {
	if !q.inTransaction {
		return fmt.Errorf("no transaction in progress")
	}

	// Send CONDOR_CommitTransactionNoFlags (10007) command
	msg := message.NewMessageForStream(q.stream)
	if err := msg.PutInt(ctx, CONDOR_CommitTransactionNoFlags); err != nil {
		return fmt.Errorf("failed to send CommitTransaction command: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish CommitTransaction message: %w", err)
	}

	// Receive response
	responseMsg := message.NewMessageFromStream(q.stream)
	rval, err := responseMsg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive CommitTransaction response: %w", err)
	}

	if rval < 0 {
		// Read error code
		errCode, err := responseMsg.GetInt(ctx)
		if err != nil {
			return fmt.Errorf("CommitTransaction failed but could not read error code: %w", err)
		}

		// Modern schedds (>= 8.3.4) send a ClassAd with error details
		// Try to read the ClassAd for more detailed error information
		errorAd, err := responseMsg.GetClassAd(ctx)
		if err != nil {
			// If we can't read the ClassAd, just return the basic error
			q.inTransaction = false
			return fmt.Errorf("CommitTransaction failed with error code %d", errCode)
		}

		// Extract error reason from the ClassAd if present
		if errorReason, ok := errorAd.EvaluateAttrString("ErrorReason"); ok && errorReason != "" {
			q.inTransaction = false
			return fmt.Errorf("CommitTransaction failed: %s (error code %d)", errorReason, errCode)
		}

		// Fallback to basic error if no reason found
		q.inTransaction = false
		return fmt.Errorf("CommitTransaction failed with error code %d", errCode)
	}

	q.inTransaction = false
	return nil
}

// AbortTransaction aborts a queue management transaction
//
//nolint:revive // ctx will be used when implementing CONDOR_AbortTransaction protocol
func (q *QmgmtConnection) AbortTransaction(ctx context.Context) error {
	if !q.inTransaction {
		return fmt.Errorf("no transaction in progress")
	}
	// TODO: Send CONDOR_AbortTransaction (10024) command
	q.inTransaction = false
	return nil
}

// NewCluster allocates a new cluster ID
func (q *QmgmtConnection) NewCluster(ctx context.Context) (int, error) {
	if !q.inTransaction {
		return -1, fmt.Errorf("must be in a transaction to create a new cluster")
	}

	// Send CONDOR_NewCluster (10002) command
	msg := message.NewMessageForStream(q.stream)
	if err := msg.PutInt(ctx, CONDOR_NewCluster); err != nil {
		return -1, fmt.Errorf("failed to send NewCluster command: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return -1, fmt.Errorf("failed to finish NewCluster message: %w", err)
	}

	// Receive response
	responseMsg := message.NewMessageFromStream(q.stream)
	clusterID, err := responseMsg.GetInt(ctx)
	if err != nil {
		return -1, fmt.Errorf("failed to receive NewCluster response: %w", err)
	}

	if clusterID < 0 {
		// Read error code
		errCode, err := responseMsg.GetInt(ctx)
		if err != nil {
			return -1, fmt.Errorf("NewCluster failed but could not read error code: %w", err)
		}
		return -1, fmt.Errorf("NewCluster failed with error code %d", errCode)
	}

	return clusterID, nil
}

// NewProc allocates a new proc ID within a cluster
func (q *QmgmtConnection) NewProc(ctx context.Context, clusterID int) (int, error) {
	if !q.inTransaction {
		return -1, fmt.Errorf("must be in a transaction to create a new proc")
	}

	// Send CONDOR_NewProc (10003) command
	msg := message.NewMessageForStream(q.stream)
	if err := msg.PutInt(ctx, CONDOR_NewProc); err != nil {
		return -1, fmt.Errorf("failed to send NewProc command: %w", err)
	}
	if err := msg.PutInt(ctx, clusterID); err != nil {
		return -1, fmt.Errorf("failed to send cluster ID: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return -1, fmt.Errorf("failed to finish NewProc message: %w", err)
	}

	// Receive response
	responseMsg := message.NewMessageFromStream(q.stream)
	procID, err := responseMsg.GetInt(ctx)
	if err != nil {
		return -1, fmt.Errorf("failed to receive NewProc response: %w", err)
	}

	if procID < 0 {
		// Read error code
		errCode, err := responseMsg.GetInt(ctx)
		if err != nil {
			return -1, fmt.Errorf("NewProc failed but could not read error code: %w", err)
		}
		return -1, fmt.Errorf("NewProc failed with error code %d", errCode)
	}

	return procID, nil
}

// SetAttribute sets an attribute on a job (cluster.proc) or cluster (cluster.-1)
func (q *QmgmtConnection) SetAttribute(ctx context.Context, clusterID, procID int, attrName, attrValue string, flags SetAttributeFlags) error {
	if !q.inTransaction {
		return fmt.Errorf("must be in a transaction to set attributes")
	}

	// Send CONDOR_SetAttribute (10006) command
	// Note: wire format is: command, cluster_id, proc_id, attr_value, attr_name
	msg := message.NewMessageForStream(q.stream)
	if err := msg.PutInt(ctx, CONDOR_SetAttribute); err != nil {
		return fmt.Errorf("failed to send SetAttribute command: %w", err)
	}
	if err := msg.PutInt(ctx, clusterID); err != nil {
		return fmt.Errorf("failed to send cluster ID: %w", err)
	}
	if err := msg.PutInt(ctx, procID); err != nil {
		return fmt.Errorf("failed to send proc ID: %w", err)
	}
	if err := msg.PutString(ctx, attrValue); err != nil {
		return fmt.Errorf("failed to send attribute value: %w", err)
	}
	if err := msg.PutString(ctx, attrName); err != nil {
		return fmt.Errorf("failed to send attribute name: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish SetAttribute message: %w", err)
	}

	// Check for NoAck flag
	if flags&SetAttributeNoAck != 0 {
		// Don't wait for response
		return nil
	}

	// Receive response
	responseMsg := message.NewMessageFromStream(q.stream)
	rval, err := responseMsg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive SetAttribute response: %w", err)
	}

	if rval < 0 {
		// Read error code
		errCode, err := responseMsg.GetInt(ctx)
		if err != nil {
			return fmt.Errorf("SetAttribute failed but could not read error code: %w", err)
		}
		return fmt.Errorf("SetAttribute failed for %s with error code %d", attrName, errCode)
	}

	return nil
}

// SetAttributeInt is a convenience method to set an integer attribute
func (q *QmgmtConnection) SetAttributeInt(ctx context.Context, clusterID, procID int, attrName string, value int, flags SetAttributeFlags) error {
	return q.SetAttribute(ctx, clusterID, procID, attrName, fmt.Sprintf("%d", value), flags)
}

// SetEffectiveOwner sets the effective owner for subsequent job operations
// This must be called before setting job attributes as it determines the owner of the jobs
func (q *QmgmtConnection) SetEffectiveOwner(ctx context.Context, owner string) error {
	if !q.inTransaction {
		return fmt.Errorf("must be in a transaction to set effective owner")
	}

	// Send CONDOR_SetEffectiveOwner (10030) command
	msg := message.NewMessageForStream(q.stream)
	if err := msg.PutInt(ctx, CONDOR_SetEffectiveOwner); err != nil {
		return fmt.Errorf("failed to send SetEffectiveOwner command: %w", err)
	}
	if err := msg.PutString(ctx, owner); err != nil {
		return fmt.Errorf("failed to send owner name: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish SetEffectiveOwner message: %w", err)
	}

	// Receive response
	responseMsg := message.NewMessageFromStream(q.stream)
	rval, err := responseMsg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive SetEffectiveOwner response: %w", err)
	}

	if rval < 0 {
		// Read error code
		errCode, err := responseMsg.GetInt(ctx)
		if err != nil {
			return fmt.Errorf("SetEffectiveOwner failed but could not read error code: %w", err)
		}
		return fmt.Errorf("SetEffectiveOwner failed for %s with error code %d", owner, errCode)
	}

	return nil
}

// DestroyCluster removes a cluster and all its procs
//
//nolint:revive // ctx will be used when implementing CONDOR_DestroyCluster protocol
func (q *QmgmtConnection) DestroyCluster(ctx context.Context, clusterID int) error {
	if !q.inTransaction {
		return fmt.Errorf("must be in a transaction to destroy a cluster")
	}
	// TODO: Send CONDOR_DestroyCluster (10004) command
	return fmt.Errorf("DestroyCluster not yet implemented")
}

// Attribute names and values this file sends explicitly, ahead of the
// generic attribute loop.
const (
	attrClusterID = "ClusterId"
	attrProcID    = "ProcId"
	attrJobStatus = "JobStatus"

	// clusterAdProcID is the proc id of a cluster's own ad.
	clusterAdProcID = -1
)

// jobStatus* constants mirror HTCondor's JobStatus enum
// (src/condor_includes/proc.h). A job is submitted as idle unless its ad says
// otherwise.
const (
	jobStatusIdle    = 1
	jobStatusRunning = 2
	jobStatusRemoved = 3
	jobStatusHeld    = 5
)

// attrPlacement says which ad an attribute is obliged to live in. It mirrors
// HTCondor's aForcedSetAttrs table (condor_schedd.V6/qmgmt_common.cpp): the
// schedd keeps cluster-wide identity and universe on the cluster ad and
// per-job identity and state on the proc ad, and ignores or redirects writes
// that arrive on the wrong one.
type attrPlacement int

const (
	// placeAny means the attribute may live in either ad.
	placeAny attrPlacement = iota
	// placeCluster means the attribute belongs only in the cluster ad.
	placeCluster
	// placeProc means the attribute belongs only in a proc ad.
	placeProc
)

// forcedAttrPlacement maps attribute names to the ad they are obliged to live
// in. Keys are lowercase because ClassAd attribute names are case-insensitive;
// look up through placementOf rather than indexing this directly.
//
// NTDomain and User are in the schedd's copy of this table but not in
// condor_submit's. They are here because the schedd silently drops them when
// they arrive on a proc ad with a proc id above zero -- it reports success
// and stores nothing -- which is a worse outcome than putting them where they
// belong.
var forcedAttrPlacement = map[string]attrPlacement{
	"clusterid":   placeCluster,
	"jobsetid":    placeCluster,
	"jobsetname":  placeCluster,
	"jobstatus":   placeProc,
	"jobuniverse": placeCluster,
	"ntdomain":    placeCluster,
	"owner":       placeCluster,
	"procid":      placeProc,
	"user":        placeCluster,
}

// placementOf reports which ad attrName is obliged to live in.
func placementOf(attrName string) attrPlacement {
	return forcedAttrPlacement[strings.ToLower(attrName)]
}

// sentAheadOfLoop holds the attributes SendClusterAttributes and
// SendProcAttributes send explicitly before the generic loop, so that the
// loop does not send them a second time.
var sentAheadOfLoop = map[string]struct{}{
	"clusterid": {},
	"procid":    {},
	"jobstatus": {},
}

// SendClusterAttributes sends an ad to a cluster's own ad, at proc id -1.
//
// Everything a submission shares across its procs belongs here. The schedd
// chains each proc ad to its cluster ad, so an attribute set here shows
// through on every proc of the cluster, and QUERY_JOB_ADS merges the chain
// before returning a proc ad, so a reader cannot tell the difference. What it
// does change: the queue holds one copy of the attribute instead of one per
// proc, and `condor_qedit <clusterid> Attr=Value` reaches every job in the
// cluster -- which it cannot do for an attribute that each proc carries its
// own copy of, because the proc's own value wins.
//
// ClusterId is sent first, as condor_submit does. Attributes obliged to live
// in a proc ad are skipped.
func (q *QmgmtConnection) SendClusterAttributes(ctx context.Context, clusterID int, ad *classad.ClassAd) error {
	if !q.inTransaction {
		return fmt.Errorf("must be in a transaction to send cluster attributes")
	}

	if err := q.SetAttributeInt(ctx, clusterID, clusterAdProcID, attrClusterID, clusterID, 0); err != nil {
		return fmt.Errorf("failed to set %s for cluster %d: %w", attrClusterID, clusterID, err)
	}

	return q.sendAdAttributes(ctx, clusterID, clusterAdProcID, ad, nil, placeCluster)
}

// SendProcAttributes sends an ad to a single proc of a cluster.
//
// clusterAd, when non-nil, is the ad already sent to the cluster at proc id
// -1. Any attribute of ad whose value is structurally identical to the
// cluster ad's is left out, because the proc inherits it through the chain.
// Pass nil to send every attribute, which is only correct when no cluster ad
// was sent for this cluster.
//
// ProcId and JobStatus are sent first and unconditionally. ProcId identifies
// the ad. JobStatus has to be present in the proc ad itself even when the
// cluster ad carries the same value, because the schedd computes its
// per-cluster and per-owner totals by state from the proc ads and gets them
// wrong when it is missing.
//
// Attributes obliged to live in the cluster ad are skipped. The schedd will
// not accept Owner, User or ProjectName on a proc whose id is above zero: it
// logs at D_FULLDEBUG and returns success without storing them, so sending
// them there is a silent no-op, not an error the caller would see.
func (q *QmgmtConnection) SendProcAttributes(ctx context.Context, clusterID, procID int, ad, clusterAd *classad.ClassAd) error {
	if !q.inTransaction {
		return fmt.Errorf("must be in a transaction to send job attributes")
	}
	if procID < 0 {
		return fmt.Errorf("invalid proc id %d: use SendClusterAttributes to send a cluster ad", procID)
	}

	if err := q.SetAttributeInt(ctx, clusterID, procID, attrProcID, procID, 0); err != nil {
		return fmt.Errorf("failed to set %s for job %d.%d: %w", attrProcID, clusterID, procID, err)
	}

	// Read the status from the proc ad, falling back to the cluster ad and
	// then to IDLE, the way condor_submit reads it back through the chain.
	status := int64(jobStatusIdle)
	for _, src := range []*classad.ClassAd{ad, clusterAd} {
		if src == nil {
			continue
		}
		if found, ok := src.EvaluateAttrInt(attrJobStatus); ok {
			status = found
			break
		}
	}
	if err := q.SetAttributeInt(ctx, clusterID, procID, attrJobStatus, int(status), 0); err != nil {
		return fmt.Errorf("failed to set %s for job %d.%d: %w", attrJobStatus, clusterID, procID, err)
	}

	return q.sendAdAttributes(ctx, clusterID, procID, ad, clusterAd, placeProc)
}

// sendAdAttributes sends every attribute of ad that belongs in the ad
// identified by (clusterID, procID), as one SetAttribute call each.
//
// keep is the placement this ad accepts: an attribute forced to the other
// placement is skipped. dedupAgainst, when non-nil, is an ad already sent
// whose values this one inherits; a structurally identical value is not
// resent.
//
// Nothing here mutates ad. Callers hand the generated proc ads out after
// submission -- SubmitRemote returns them for file spooling, which reads Cmd
// and the transfer lists back off them -- so dropping a deduplicated
// attribute from the ad itself would empty out the spool's allow-set and lose
// the files in silence.
func (q *QmgmtConnection) sendAdAttributes(
	ctx context.Context,
	clusterID, procID int,
	ad, dedupAgainst *classad.ClassAd,
	keep attrPlacement,
) error {
	for _, attr := range selectAttributes(ad, dedupAgainst, keep) {
		expr, ok := ad.Lookup(attr)
		if !ok || expr == nil {
			continue
		}
		if err := q.SetAttribute(ctx, clusterID, procID, attr, expr.String(), 0); err != nil {
			return fmt.Errorf("failed to set attribute %s: %w", attr, err)
		}
	}

	return nil
}

// selectAttributes returns the names of the attributes of ad that belong in an
// ad of the given placement and are not already covered, in the order ad holds
// them.
//
// An attribute is left out when it is sent ahead of the loop (ClusterId,
// ProcId, JobStatus), when it is obliged to live in the other kind of ad, or
// when dedupAgainst is non-nil and already holds a structurally identical
// value -- a chained proc ad inherits that value, so resending it would only
// add a second copy to the queue.
//
// An attribute that dedupAgainst holds and ad does not is *not* reported:
// there is no way to hide a cluster ad's attribute from a chained proc ad by
// leaving it out, and condor_submit has the same behavior. Submissions whose
// procs differ in which attributes are present at all -- a value-conditional
// one like container_image, where a queue item expands to the empty string --
// therefore inherit the first proc's value rather than having none.
func selectAttributes(ad, dedupAgainst *classad.ClassAd, keep attrPlacement) []string {
	if ad == nil {
		return nil
	}

	attrs := ad.GetAttributes()
	selected := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		if _, sent := sentAheadOfLoop[strings.ToLower(attr)]; sent {
			continue
		}
		if place := placementOf(attr); place != placeAny && place != keep {
			continue
		}

		expr, ok := ad.Lookup(attr)
		if !ok || expr == nil {
			continue
		}

		if dedupAgainst != nil {
			if parent, ok := dedupAgainst.Lookup(attr); ok && expr.Equal(parent) {
				continue
			}
		}

		selected = append(selected, attr)
	}

	return selected
}

// SendJobAttributes sends every attribute of ad to one job, (clusterID,
// procID), with no attention to which ad the schedd will actually store each
// one in.
//
// Deprecated: use SendClusterAttributes and SendProcAttributes instead. This
// sends a cluster's shared attributes once per proc rather than once to the
// cluster ad, which costs a round trip per attribute per proc and leaves each
// proc holding its own copy, so condor_qedit on the cluster id does not reach
// those jobs. Owner, User and ProjectName sent this way for proc > 0 are
// discarded by the schedd, which reports success. The behavior is kept as it
// was for callers that depend on it.
func (q *QmgmtConnection) SendJobAttributes(ctx context.Context, clusterID, procID int, ad *classad.ClassAd) error {
	if !q.inTransaction {
		return fmt.Errorf("must be in a transaction to send job attributes")
	}

	for _, attr := range ad.GetAttributes() {
		expr, ok := ad.Lookup(attr)
		if !ok || expr == nil {
			continue
		}

		if err := q.SetAttribute(ctx, clusterID, procID, attr, expr.String(), 0); err != nil {
			return fmt.Errorf("failed to set attribute %s: %w", attr, err)
		}
	}

	return nil
}

// QMGMT Protocol Implementation Notes:
//
// The queue management protocol (QMGMT) is used for job submission and modification.
// It operates over a CEDAR connection after security handshake.
//
// Protocol flow for job submission:
// 1. Establish TCP connection to schedd
// 2. Perform DC_AUTHENTICATE handshake
// 3. Send QMGMT_WRITE_CMD (1112) to enter queue management mode
// 4. Send CONDOR_GetCapabilities (10036) to query schedd capabilities
// 5. Send CONDOR_BeginTransaction (10023)
// 6. Send CONDOR_NewCluster (10002) -> receives cluster ID
// 7. Send CONDOR_NewProc (10003, cluster_id) -> receives proc ID
// 8. Send CONDOR_SetAttribute (10006, cluster, proc, attr, value) for each attribute
//    - Or CONDOR_SetAttribute2 (10027) with flags
//    - Can use SetAttributeNoAck flag to avoid waiting for each ACK
// 9. Repeat steps 7-8 for additional procs in the cluster
// 10. Send CONDOR_CommitTransactionNoFlags (10007)
// 11. Send CONDOR_CloseSocket (10028)
//
// Wire format for each command:
// - Command ID (int32)
// - Command-specific parameters
// - End of message marker
// - Response: status code (int32), then command-specific response
//
// Key differences from collector query protocol:
// - Uses QMGMT_WRITE_CMD instead of query commands
// - Requires transaction management
// - Each operation has explicit success/failure response
// - Attributes sent as individual SetAttribute calls, not as complete ClassAd
//
// References:
// - reference/qmgmt_send_stubs.cpp - client-side QMGMT protocol implementation
// - reference/submit_protocol.cpp - ActualScheddQ implementation
// - reference/submit.cpp - condor_submit usage of QMGMT protocol
