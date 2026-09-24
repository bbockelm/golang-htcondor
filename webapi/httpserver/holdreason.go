package httpserver

import "github.com/bbockelm/golang-htcondor/webapi/issues"

// holdReasonLabel names a hold code for the dashboard and the issues
// endpoint.
//
// The table moved to webapi/issues when the MCP tool started needing it
// too: both servers turn a code into words, and two tables would drift
// into naming the same code differently depending on which surface the
// reader was looking at.
func holdReasonLabel(code int64) string { return issues.HoldReasonLabel(code) }

// holdReasonIsRoutine reports whether a hold is part of normal operation
// rather than a failure.
func holdReasonIsRoutine(code int64) bool { return issues.HoldReasonIsRoutine(code) }
