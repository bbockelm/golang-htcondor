package multiap

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/PelicanPlatform/classad/dbrpc"

	"github.com/bbockelm/golang-htcondor/webapi/dbmirror"
)

// Page tokens of the live job list.
//
// The job list pages on a commit-sequence cursor (dbrpc.SeqCursor): a
// position in ONE hub's store. Another hub's sequence numbers are
// unrelated, so a cursor resumed there skips or repeats rows without any
// error. A token therefore names the hub that issued it, and a page
// asked of another hub is refused with a 400 telling the caller to start
// over. The name alone is enough: a hub's cursor stays good on that hub,
// so leaving it and coming back (A, B, A) resumes.
//
// The history list's token is a value key (EnteredHistoryTime,
// ScheddName, ClusterId, ProcId) that any hub orders the same way, and is
// not bound to one.

// jobsTokenPrefix marks a hub-bound job list token: "jh1:<hub>:<cursor>",
// the hub's name base64url-encoded and the cursor a dbmirror token.
const jobsTokenPrefix = "jh1:"

// ReasonRestartPaging is the reason of a page token another hub issued.
const ReasonRestartPaging = "restart_pagination"

func encodeJobsToken(hub string, c dbrpc.SeqCursor) string {
	return jobsTokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(hub)) + ":" + dbmirror.EncodeCursor(c)
}

// decodeJobsToken reads a job list token issued by hub. A token from
// another hub, or one from before tokens named their hub, is a 400 with
// ReasonRestartPaging.
func decodeJobsToken(token, hub string) (dbrpc.SeqCursor, error) {
	restart := &Error{Status: http.StatusBadRequest, Reason: ReasonRestartPaging,
		Msg: "this page token was issued by another federation hub than the one serving reads now; " +
			"restart pagination from the first page (omit page_token)"}
	if dbmirror.IsCursor(token) {
		return dbrpc.SeqCursor{}, restart
	}
	rest, ok := strings.CutPrefix(token, jobsTokenPrefix)
	if !ok {
		return dbrpc.SeqCursor{}, errorf(http.StatusBadRequest, "this page token was not issued for the multi-AP job list")
	}
	enc, cur, ok := strings.Cut(rest, ":")
	if !ok {
		return dbrpc.SeqCursor{}, errorf(http.StatusBadRequest, "unreadable page token")
	}
	name, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return dbrpc.SeqCursor{}, errorf(http.StatusBadRequest, "unreadable page token: %v", err)
	}
	if !strings.EqualFold(string(name), hub) {
		return dbrpc.SeqCursor{}, restart
	}
	c, err := dbmirror.DecodeCursor(cur)
	if err != nil {
		return dbrpc.SeqCursor{}, errorf(http.StatusBadRequest, "unreadable page token: %v", err)
	}
	return c, nil
}
