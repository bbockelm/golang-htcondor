package dbmirror

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/PelicanPlatform/classad/dbrpc"
)

// A page token names which backend issued it, because the two cannot read
// each other's. The schedd's is a (ClusterId, ProcId) position in its own
// queue walk; the mirror's is a storage cursor — a shard, that shard's
// snapshot, and a position in its commit sequence. Handing either to the
// other backend would silently resume somewhere else, so the token says
// where it came from and a caller that cannot honor it says so instead of
// guessing.
const mirrorTokenPrefix = "db1:"

// mirrorToken is what a mirror-issued page token carries.
type mirrorToken struct {
	Shard    uint32 `json:"s"`
	Snapshot uint64 `json:"v"`
	Seq      uint64 `json:"q"`
	Key      string `json:"k"`
}

// EncodeCursor renders a mirror cursor as a page token. The prefix marks it
// as this backend's, so a schedd-issued token is never mistaken for one.
func EncodeCursor(c dbrpc.SeqCursor) string {
	raw, err := json.Marshal(mirrorToken{Shard: c.Shard, Snapshot: c.Snapshot, Seq: c.Seq, Key: c.Key})
	if err != nil {
		// The struct is four scalars and a string; marshaling cannot fail.
		// Returning an empty token would silently restart pagination, so
		// panic-free but loud: the caller sees no next page.
		return ""
	}
	return mirrorTokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

// IsCursor reports whether a page token was issued by the mirror.
func IsCursor(token string) bool {
	return len(token) > len(mirrorTokenPrefix) && token[:len(mirrorTokenPrefix)] == mirrorTokenPrefix
}

// DecodeCursor parses a mirror-issued page token. It errors on a token that
// is not the mirror's, or is malformed — never returning a zero cursor,
// which would silently restart the caller at the beginning.
func DecodeCursor(token string) (dbrpc.SeqCursor, error) {
	if !IsCursor(token) {
		return dbrpc.SeqCursor{}, fmt.Errorf("not an htcondordb page token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(token[len(mirrorTokenPrefix):])
	if err != nil {
		return dbrpc.SeqCursor{}, fmt.Errorf("malformed htcondordb page token: %w", err)
	}
	var t mirrorToken
	if err := json.Unmarshal(raw, &t); err != nil {
		return dbrpc.SeqCursor{}, fmt.Errorf("malformed htcondordb page token: %w", err)
	}
	return dbrpc.SeqCursor{Shard: t.Shard, Snapshot: t.Snapshot, Seq: t.Seq, Key: t.Key}, nil
}
