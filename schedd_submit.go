package htcondor

import (
	"context"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/client"
	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/cedar/security"
	"github.com/bbockelm/cedar/stream"
)

// SetAttributeFlags controls behavior when setting job attributes
type SetAttributeFlags int

const (
	// SetAttributeNoAck indicates not to wait for acknowledgment when setting attributes
	SetAttributeNoAck SetAttributeFlags = 1 << 0
)

// QMGMT Protocol Commands (from qmgmt_constants.h)
// These constants match HTCondor's internal command codes and use underscores to match the C++ naming
//
//nolint:revive // Protocol constants match HTCondor C++ naming convention
const (
	CONDOR_NewCluster               = 10002
	CONDOR_NewProc                  = 10003
	CONDOR_DestroyCluster           = 10004
	CONDOR_SetAttribute             = 10006
	CONDOR_SetAttribute2            = 10027
	CONDOR_BeginTransaction         = 10023
	CONDOR_CommitTransactionNoFlags = 10007
	CONDOR_CommitTransaction        = 10031
	CONDOR_AbortTransaction         = 10024
	CONDOR_SetEffectiveOwner        = 10030
	CONDOR_GetCapabilities          = 10036
	CONDOR_CloseSocket              = 10028
	QMGMT_WRITE_CMD                 = 1112
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
	// Get SecurityConfig from context, HTCondor config, or defaults
	secConfig, err := GetSecurityConfigOrDefault(ctx, nil, QMGMT_WRITE_CMD, "CLIENT", address)
	if err != nil {
		return nil, fmt.Errorf("failed to create security config: %w", err)
	}

	// Note: We use manual authentication here instead of ConnectAndAuthenticate because we need
	// access to the negotiation result to get the authenticated user and verify auth method.
	// Establish connection using cedar client
	htcondorClient, err := client.ConnectToAddress(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to schedd at %s: %w", address, err)
	}

	// Get CEDAR stream from client
	cedarStream := htcondorClient.GetStream()

	// Perform DC_AUTHENTICATE handshake
	auth := security.NewAuthenticator(secConfig, cedarStream)
	negotiation, err := auth.ClientHandshake(ctx)
	if err != nil {
		_ = htcondorClient.Close()
		return nil, fmt.Errorf("authentication handshake failed: %w", err)
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

// SendJobAttributes sends all attributes from a ClassAd to the schedd for a specific job
// This iterates through the ClassAd and calls SetAttribute for each attribute
func (q *QmgmtConnection) SendJobAttributes(ctx context.Context, clusterID, procID int, ad *classad.ClassAd) error {
	if !q.inTransaction {
		return fmt.Errorf("must be in a transaction to send job attributes")
	}

	// Iterate through all attributes in the ClassAd and send them
	for _, attr := range ad.GetAttributes() {
		expr, ok := ad.Lookup(attr)
		if !ok || expr == nil {
			continue
		}

		// Convert the expression to a string representation
		valueStr := expr.String()

		if err := q.SetAttribute(ctx, clusterID, procID, attr, valueStr, 0); err != nil {
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
