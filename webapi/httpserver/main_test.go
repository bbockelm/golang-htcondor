package httpserver

import (
	"os"
	"testing"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// TestMain runs the unit suite with unclassified contexts refused at the
// daemon fallback, as a deployment that has finished classifying them
// would. A code path that reaches CEDAR on a context nobody marked --
// neither a caller's request nor this daemon's own work -- then fails here
// instead of quietly authenticating as the daemon. See testOriginPolicy for
// the integration build.
func TestMain(m *testing.M) {
	htcondor.SetUnmarkedOriginPolicy(testOriginPolicy)
	os.Exit(m.Run())
}
