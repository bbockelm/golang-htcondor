package usagestats

// Spec describes one kind of counted call.
//
// The machinery in this package -- the bounded store, the SQLite
// round trip, the const-metric collector, the aggregation the admin
// page renders -- is the same whether the thing being counted is an
// MCP tool or a REST endpoint. What differs is only the vocabulary:
// what the first dimension is called, which outcomes are possible,
// which table the totals live in, and what the metrics are named.
//
// Keeping that difference in one value rather than in two copies of
// the package is what lets a fix to the overflow bound, the flush
// safety check or the percentile apply to both at once. Each Store
// carries exactly one Spec and never mixes kinds: the table's primary
// key, the Prometheus label set and the admin page's columns all
// assume a single vocabulary.
type Spec struct {
	// Kind is the stable identifier a caller selects this spec by --
	// the `kind` query parameter on the admin endpoint, and the tab in
	// the UI. Do not rename one: it is in URLs.
	Kind string

	// Noun is the singular, lower-case word for what Key.Name holds:
	// "tool" for MCP, "endpoint" for REST. It is the Prometheus label
	// name, the JSON filter key, and the middle word of every metric
	// name, so it is as much a wire contract as Kind is.
	Noun string

	// Title is the human label for Noun, capitalised for a column
	// heading ("Tool", "Endpoint").
	Title string

	// Table is the SQLite table holding the durable totals, and
	// NameColumn is the column within it that Key.Name is stored in.
	//
	// Both are interpolated into SQL. They are compile-time constants
	// from this file and never reach it from a request; there is no
	// path by which a caller chooses either.
	Table      string
	NameColumn string

	// Subsystem is the Prometheus subsystem the metrics sit under, so
	// MCP's counters stay at htcondor_api_mcp_tool_* where existing
	// dashboards expect them while REST's appear beside them rather
	// than on top of them.
	Subsystem string

	// Outcomes is the bounded vocabulary of things that can happen to
	// a call, in the order the admin page shows its columns. Bounded
	// because it is a Prometheus label; ordered because the first one
	// is conventionally the success case and a reader scans left to
	// right.
	Outcomes []string

	// DefaultOutcome is recorded when a caller passes an empty string.
	// It is deliberately a failure in both specs: a call whose outcome
	// nobody set is not evidence that it worked.
	DefaultOutcome string

	// ExportDurations says whether the duration histogram is published
	// to Prometheus. The store and the table always keep durations --
	// the admin page's Avg and p95 come from them either way -- but a
	// histogram costs one series per bucket per label combination, and
	// a kind whose latency another metric already covers should not
	// pay that twice.
	ExportDurations bool

	// Help strings for the four exported metrics. Written per kind
	// rather than generated from Noun: these are what an operator
	// reads in a metrics browser, and the useful half of each is the
	// part that is specific to the kind.
	CallsHelp    string
	DurationHelp string
	LastCallHelp string
	UsersHelp    string
}

// Outcome values shared by both specs.
const (
	// OutcomeOK is a call that did what it was asked.
	OutcomeOK = "ok"
	// OutcomeError is a call that failed in a way attributable to this
	// server or to what it depends on.
	OutcomeError = "error"
)

// MCP-only outcomes.
const (
	// OutcomeUnknownTool is a call that named a tool this server does
	// not have. Its own outcome rather than an error, because it says
	// the caller's catalogue is wrong -- a stale client, or an agent
	// inventing a name -- which is a different problem from a tool
	// that ran and failed.
	OutcomeUnknownTool = "unknown_tool"
	// OutcomeRefused is a tool call rejected before the tool ran --
	// today, one disabled by configuration. Separated from "error"
	// because it says something about the deployment rather than about
	// the call: a dashboard that lumps them together reports a policy
	// decision as a malfunction.
	OutcomeRefused = "refused"
)

// REST-only outcomes. The split exists for the same reason MCP
// separates "refused" from "error": an operator looking at a spike
// needs to know whether the server is broken, the caller is, or policy
// is doing its job, and a single "error" bucket answers none of them.
const (
	// OutcomeDenied is 401 or 403: the caller was turned away by
	// authentication or authorization.
	OutcomeDenied = "denied"
	// OutcomeNotFound is 404. Kept apart from the other 4xx because on
	// a REST API it usually means a stale client or a job that has
	// since left the queue, not a malformed request.
	OutcomeNotFound = "not_found"
	// OutcomeRateLimited is 429, which is policy working rather than
	// anything failing.
	OutcomeRateLimited = "rate_limited"
	// OutcomeClientError is any other 4xx: a request this server
	// understood and judged wrong.
	OutcomeClientError = "client_error"
)

// MCPSpec counts MCP tool calls.
func MCPSpec() Spec {
	return Spec{
		Kind:       "mcp",
		Noun:       "tool",
		Title:      "Tool",
		Table:      "mcp_tool_stats",
		NameColumn: "tool",
		Subsystem:  "mcp",
		Outcomes: []string{
			OutcomeOK, OutcomeError, OutcomeRefused, OutcomeUnknownTool,
		},
		DefaultOutcome:  OutcomeError,
		ExportDurations: true,
		CallsHelp: "MCP tool calls, by tool, user, client harness and outcome (ok/error/refused). " +
			"Resumed from the persisted totals at startup, so this counts the lifetime of the " +
			"deployment rather than of the process.",
		DurationHelp: "MCP tool call duration. Labelled by tool, client and outcome but NOT by user: " +
			"how long a tool takes is a property of the tool and the pool, not of who asked, " +
			"and a histogram carries fourteen series per label combination.",
		LastCallHelp: "Unix timestamp of the most recent call to each tool. Only tools that have been " +
			"called appear here, so this answers \"how long since this was used\" and not " +
			"\"is this tool used at all\" -- a tool nobody has ever called has no series.",
		UsersHelp: "Distinct users that have called each tool, over the whole retained history. " +
			"Counted over the verbatim user names, so it stays accurate even where the user " +
			"label has collapsed to \"other\" or been turned off.",
	}
}

// RESTSpec counts REST API requests.
//
// Key.Name is "METHOD /route/template" -- the method matters, because
// GET and DELETE on the same path are different operations with
// different risk, and folding them together would hide which one a
// caller is making.
func RESTSpec() Spec {
	return Spec{
		Kind:       "rest",
		Noun:       "endpoint",
		Title:      "Endpoint",
		Table:      "rest_endpoint_stats",
		NameColumn: "endpoint",
		Subsystem:  "rest",
		Outcomes: []string{
			OutcomeOK, OutcomeDenied, OutcomeNotFound,
			OutcomeRateLimited, OutcomeClientError, OutcomeError,
		},
		DefaultOutcome: OutcomeError,
		// htcondor_api_http_request_duration_seconds already publishes
		// this server's latency by method and route. A second
		// histogram over the same requests would add a bucket series
		// per (endpoint, client, outcome) and tell a scraper nothing
		// the first does not. The durations are still counted and
		// still persisted; the admin page reads them from the store.
		ExportDurations: false,
		CallsHelp: "REST API requests, by endpoint, user, client and outcome. Unlike " +
			"htcondor_api_http_requests_total, which counts what this PROCESS has served and " +
			"says nothing about who asked, this is resumed from the persisted totals at startup " +
			"and is attributed to a user and a client.",
		DurationHelp: "REST API request duration, by endpoint, client and outcome.",
		LastCallHelp: "Unix timestamp of the most recent request to each endpoint. Only endpoints " +
			"that have been called appear here, so this answers \"how long since this was used\" " +
			"and not \"does this endpoint exist\".",
		UsersHelp: "Distinct users that have called each endpoint, over the whole retained history. " +
			"Counted over the verbatim user names, so it stays accurate even where the user " +
			"label has collapsed to \"other\" or been turned off.",
	}
}

// Specs returns every kind, in the order the UI offers them.
func Specs() []Spec { return []Spec{MCPSpec(), RESTSpec()} }

// SpecForKind returns the spec with the given Kind. The second result
// is false for a kind nobody defines, which is how the admin endpoint
// rejects an unknown `kind` parameter rather than quietly answering
// about the wrong one.
func SpecForKind(kind string) (Spec, bool) {
	for _, s := range Specs() {
		if s.Kind == kind {
			return s, true
		}
	}
	return Spec{}, false
}

// knownOutcome reports whether o is in this spec's vocabulary.
func (s Spec) knownOutcome(o string) bool {
	for _, v := range s.Outcomes {
		if v == o {
			return true
		}
	}
	return false
}
