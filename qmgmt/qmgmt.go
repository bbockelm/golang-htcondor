// Package qmgmt holds the shared codec for HTCondor's QMGMT (queue management)
// wire protocol: the operation constants, the SetAttribute flag bits, and the
// reply framing convention. Both the QMGMT client in the parent package and a
// QMGMT server (e.g. golang-ap's schedd) consume it so the byte-level protocol
// lives in exactly one place.
//
// The op constants and framing were verified against HTCondor's C++ reference:
// src/condor_schedd.V6/qmgmt_constants.h (op numbers),
// src/condor_schedd.V6/qmgmt_receivers.cpp (do_Q_request, the server switch),
// src/condor_schedd.V6/qmgmt_send_stubs.cpp (the client stubs), and
// src/condor_includes/condor_qmgr.h (the flag bits).
package qmgmt

import (
	"context"

	"github.com/bbockelm/cedar/message"
)

// DaemonCore command integers that put a socket into QMGMT mode. After the
// DC_AUTHENTICATE handshake negotiates one of these, the peer speaks the QMGMT
// RPC loop (op int + args + EOM -> rval int [+ terrno] [+ payload] + EOM) on the
// same stream until it sends CloseSocket.
const (
	// ReadCmd (QMGMT_READ_CMD) opens a read-only queue connection.
	ReadCmd = 1111
	// WriteCmd (QMGMT_WRITE_CMD) opens a read/write queue connection; it forces
	// authentication so the schedd learns the submitting user.
	WriteCmd = 1112
)

// QMGMT operation codes (qmgmt_constants.h). These are the op integers read at
// the top of each RPC-loop iteration.
const (
	OpNewCluster               = 10002
	OpNewProc                  = 10003
	OpDestroyCluster           = 10004
	OpDestroyProc              = 10005
	OpSetAttribute             = 10006
	OpCommitTransactionNoFlags = 10007
	OpGetAttributeFloat        = 10008
	OpGetAttributeInt          = 10009
	OpGetAttributeString       = 10010
	OpGetAttributeExpr         = 10011
	OpDeleteAttribute          = 10012
	OpSendSpoolFile            = 10017
	OpGetJobAd                 = 10018
	OpGetJobByConstraint       = 10019
	OpGetNextJobByConstraint   = 10020
	OpBeginTransaction         = 10023
	OpAbortTransaction         = 10024
	OpSetTimerAttribute        = 10025
	OpGetAllJobsByConstraint   = 10026
	OpSetAttribute2            = 10027
	OpCloseSocket              = 10028
	OpSendSpoolFileIfNeeded    = 10029
	OpSetEffectiveOwner        = 10030
	OpCommitTransaction        = 10031
	OpGetDirtyAttributes       = 10033
	OpSetAllowProtectedChanges = 10035
	OpGetCapabilities          = 10036
	OpSetJobFactory            = 10037
	OpSetMaterializeData       = 10038
	OpSendMaterializeData      = 10039
	OpSendJobQueueAd           = 10040
)

// SetAttributeFlags are the public wire flags carried by SetAttribute2 (op
// 10027) as a single byte. Values match SetAttributeFlags_t in condor_qmgr.h.
type SetAttributeFlags uint8

const (
	// SetNonDurable requests the schedd skip fsync for this write (1<<0).
	SetNonDurable SetAttributeFlags = 1 << 0
	// SetNoAck tells the schedd to send NO reply for this SetAttribute; any
	// failure is deferred to commit time (1<<1). condor_submit sets this by
	// default (SUBMIT_NOACK_ON_SETATTRIBUTE defaults to true).
	SetNoAck SetAttributeFlags = 1 << 1
	// SetDirty marks the attribute dirty (1<<2).
	SetDirty SetAttributeFlags = 1 << 2
	// SetShouldLog asks the schedd to log the change (1<<3).
	SetShouldLog SetAttributeFlags = 1 << 3
	// SetOnlyMyJobs restricts a by-constraint set to the caller's jobs (1<<4).
	SetOnlyMyJobs SetAttributeFlags = 1 << 4
	// SetQueryOnly performs no write, only an authorization probe (1<<5).
	SetQueryOnly SetAttributeFlags = 1 << 5

	// PublicFlagsMask is the set of bits carried on the wire (condor_qmgr.h).
	PublicFlagsMask SetAttributeFlags = 0xFF
)

// CapabilityHelpText is the GetsScheddCapabilities help-text mask bit (condor_qmgr.h).
const CapabilityHelpText = 0x01

// WriteReply writes the standard QMGMT reply header on an encode-mode message:
// the int rval, followed by the int terrno only when rval < 0. It does NOT
// finish the message; the caller appends any payload (a value or ClassAd) and
// calls FinishMessage. This is the send side of the convention ReadReply reads.
func WriteReply(ctx context.Context, m *message.Message, rval, terrno int) error {
	if err := m.PutInt(ctx, rval); err != nil {
		return err
	}
	if rval < 0 {
		if err := m.PutInt(ctx, terrno); err != nil {
			return err
		}
	}
	return nil
}

// ReadReply reads the standard QMGMT reply header from a decode-mode message:
// the int rval and, when rval < 0, the int terrno. terrno is 0 when rval >= 0.
// The caller reads any trailing payload itself.
func ReadReply(ctx context.Context, m *message.Message) (rval int, terrno int, err error) {
	rval, err = m.GetInt(ctx)
	if err != nil {
		return 0, 0, err
	}
	if rval < 0 {
		terrno, err = m.GetInt(ctx)
		if err != nil {
			return rval, 0, err
		}
	}
	return rval, terrno, nil
}
