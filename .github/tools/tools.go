//go:build tools

// Package tools pins the external binaries CI builds. It is never
// imported; the build tag keeps it out of ordinary builds while still
// making the import a real dependency Dependabot can see and bump.
package tools

import (
	// htcondordb: the database the webapi's mirror routing talks to.
	// Built by CI so webapi/httpserver's integration test can run
	// against a real one instead of a stub. See ../../webapi/httpserver
	// (dbmirror_integration_test.go).
	_ "github.com/bbockelm/htcondordb/cmd/htcondordb"

	// gotestsum: CI's test runner, for JUnit output and coverage
	// profiles. Pinned here rather than `go install ...@latest` in a
	// workflow, so the version is recorded in this module's go.sum,
	// verified on download, and bumped by Dependabot under the same
	// cooldown as everything else -- instead of resolving to whatever
	// was published minutes before the job started.
	_ "gotest.tools/gotestsum"
)
