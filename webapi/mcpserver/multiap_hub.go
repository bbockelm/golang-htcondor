package mcpserver

// Multi-AP mode: the tools served over the federation hub, or routed to
// one AP, beyond the job reads and actions.

// multiAPHubTools are served in multi-AP mode by their single-AP
// implementations, which consult the multi-AP service where it matters.
// The watch tools run on one evaluator over the hub, for every AP.
var multiAPHubTools = map[string]bool{
	"watch_jobs":       true,
	"check_watches":    true,
	"cancel_watch":     true,
	"create_watch_url": true,
}

// multiAPWatchNote is what watch_jobs adds on a multi-AP server.
const multiAPWatchNote = "\n\nOn this server a watch covers your jobs on every access point: add ScheddName to the constraint " +
	"to watch one. Each job it reports carries its access point (schedd); the same cluster.proc on two access points is " +
	"two jobs. A job on an access point whose data is not current is not reported finished until that data catches up " +
	"or its history record arrives."

// multiAPHubToolDef adjusts a served tool's description for multi-AP
// mode.
func multiAPHubToolDef(t Tool) Tool {
	if t.Name == "watch_jobs" {
		t.Description += multiAPWatchNote
	}
	return t
}
