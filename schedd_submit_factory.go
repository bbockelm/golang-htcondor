package htcondor

// The two QMGMT operations a late-materialization submission needs:
// SendMaterializeData, which spools the itemdata at the schedd, and
// SetJobFactory, which hands over the submit digest and the materialize
// limit. Both are only valid while the cluster they name is the one being
// submitted -- the schedd checks the id against the transaction's active
// cluster and refuses with EPERM otherwise -- so they go between NewCluster
// and CommitTransaction, in that order, because the digest's queue statement
// names the file SendMaterializeData reports.

import (
	"context"
	"fmt"

	"github.com/bbockelm/cedar/message"
	"github.com/bbockelm/golang-htcondor/qmgmt"
)

// materializeChunkSize is how much itemdata goes out per raw write, matching
// SendMaterializeData's own buffer. A single row larger than this cannot be
// sent at all.
const materializeChunkSize = 0x10000

// AllowsLateMaterialize reports whether this schedd will accept a job
// factory. It is false both when the schedd refuses late materialization
// (SCHEDD_ALLOW_LATE_MATERIALIZE is off) and when it is too old to have an
// opinion.
//
// condor_submit falls back to materializing every proc itself when this is
// false, and only fails the submission when the user asked for a factory
// explicitly. A submit file's max_materialize or max_idle is not that kind of
// ask.
func (q *QmgmtConnection) AllowsLateMaterialize() bool {
	return q != nil && q.allowsLateMat
}

// LateMaterializeVersion reports the late-materialization protocol version
// the schedd advertises, and whether it advertised one at all. A schedd that
// knows about late materialization but has it switched off still reports a
// version, which is what distinguishes "refused" from "too old".
func (q *QmgmtConnection) LateMaterializeVersion() (int, bool) {
	if q == nil {
		return 0, false
	}
	return q.lateMaterializeVer, q.lateMaterializeVer != 0
}

// SendMaterializeData spools a factory's itemdata rows at the schedd and
// returns the path it wrote them to and the number of rows it read.
//
// Each row must already be encoded the way the schedd expects: fields joined
// with the ASCII unit separator and the row terminated by a newline, which is
// what JobFactory.Items holds.
//
// The returned path is what the submit digest's queue statement has to name,
// so this runs before SetJobFactory.
func (q *QmgmtConnection) SendMaterializeData(ctx context.Context, clusterID int, rows []string) (string, int, error) {
	if !q.inTransaction {
		return "", 0, fmt.Errorf("must be in a transaction to send materialize data")
	}

	msg := message.NewMessageForStream(q.stream)
	if err := msg.PutInt(ctx, qmgmt.OpSendMaterializeData); err != nil {
		return "", 0, fmt.Errorf("failed to send SendMaterializeData command: %w", err)
	}
	if err := msg.PutInt(ctx, clusterID); err != nil {
		return "", 0, fmt.Errorf("failed to send cluster ID: %w", err)
	}
	// flags: no flag is defined today and condor_submit sends zero.
	if err := msg.PutInt(ctx, 0); err != nil {
		return "", 0, fmt.Errorf("failed to send SendMaterializeData flags: %w", err)
	}

	// The rows go out as raw bytes, gathered into chunks rather than one
	// write per row, which is what bounds a million-row submission's
	// memory. A row too big to fit in an empty chunk cannot be sent.
	buf := make([]byte, 0, materializeChunkSize)
	for _, row := range rows {
		if len(row)+len(buf) > materializeChunkSize {
			if len(buf) == 0 {
				return "", 0, fmt.Errorf("itemdata row of %d bytes exceeds the %d byte limit", len(row), materializeChunkSize)
			}
			if err := msg.PutBytes(ctx, buf); err != nil {
				return "", 0, fmt.Errorf("failed to send itemdata: %w", err)
			}
			buf = buf[:0]
		}
		buf = append(buf, row...)
	}
	if len(buf) > 0 {
		if err := msg.PutBytes(ctx, buf); err != nil {
			return "", 0, fmt.Errorf("failed to send itemdata: %w", err)
		}
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return "", 0, fmt.Errorf("failed to finish SendMaterializeData message: %w", err)
	}

	// The reply leads with the spooled filename and the row count, and only
	// then says whether it worked.
	responseMsg := message.NewMessageFromStream(q.stream)
	filename, err := responseMsg.GetString(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("failed to receive spooled itemdata filename: %w", err)
	}
	numItems, err := responseMsg.GetInt(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("failed to receive itemdata row count: %w", err)
	}
	rval, err := responseMsg.GetInt(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("failed to receive SendMaterializeData response: %w", err)
	}
	if rval < 0 {
		errCode, err := responseMsg.GetInt(ctx)
		if err != nil {
			return "", 0, fmt.Errorf("SendMaterializeData failed but could not read error code: %w", err)
		}
		return "", 0, fmt.Errorf("SendMaterializeData failed for cluster %d with error code %d", clusterID, errCode)
	}
	if numItems != len(rows) {
		return "", 0, fmt.Errorf("schedd stored %d itemdata rows of the %d sent", numItems, len(rows))
	}
	return filename, numItems, nil
}

// SetJobFactory hands the schedd the submit digest and the materialize limit,
// which is what makes the cluster a factory. The schedd parses the digest
// before replying, so an error here is usually the digest failing to parse.
//
// filename names a digest already on the schedd's disk and is empty for the
// ordinary case, where the digest travels in text.
func (q *QmgmtConnection) SetJobFactory(ctx context.Context, clusterID, maxMaterialize int, filename, text string) error {
	if !q.inTransaction {
		return fmt.Errorf("must be in a transaction to set a job factory")
	}

	msg := message.NewMessageForStream(q.stream)
	if err := msg.PutInt(ctx, qmgmt.OpSetJobFactory); err != nil {
		return fmt.Errorf("failed to send SetJobFactory command: %w", err)
	}
	if err := msg.PutInt(ctx, clusterID); err != nil {
		return fmt.Errorf("failed to send cluster ID: %w", err)
	}
	if err := msg.PutInt(ctx, maxMaterialize); err != nil {
		return fmt.Errorf("failed to send materialize limit: %w", err)
	}
	if err := msg.PutString(ctx, filename); err != nil {
		return fmt.Errorf("failed to send factory filename: %w", err)
	}
	if err := msg.PutString(ctx, text); err != nil {
		return fmt.Errorf("failed to send submit digest: %w", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		return fmt.Errorf("failed to finish SetJobFactory message: %w", err)
	}

	responseMsg := message.NewMessageFromStream(q.stream)
	rval, err := responseMsg.GetInt(ctx)
	if err != nil {
		return fmt.Errorf("failed to receive SetJobFactory response: %w", err)
	}
	if rval < 0 {
		errCode, err := responseMsg.GetInt(ctx)
		if err != nil {
			return fmt.Errorf("SetJobFactory failed but could not read error code: %w", err)
		}
		return fmt.Errorf("SetJobFactory failed for cluster %d with error code %d", clusterID, errCode)
	}
	return nil
}

// sendFactory performs a late-materialization submission of f into an open
// transaction whose active cluster is f.ClusterID: the itemdata first, then
// the digest naming where the schedd put it.
func (q *QmgmtConnection) sendFactory(ctx context.Context, f *JobFactory) error {
	itemsFilename := ""
	if len(f.Items) > 0 {
		name, _, err := q.SendMaterializeData(ctx, f.ClusterID, f.Items)
		if err != nil {
			return err
		}
		itemsFilename = name
	}
	digest, err := f.Digest(itemsFilename)
	if err != nil {
		return err
	}
	return q.SetJobFactory(ctx, f.ClusterID, f.MaxMaterialize, "", digest)
}
