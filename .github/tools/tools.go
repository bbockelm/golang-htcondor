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

	// nfpm: builds the release RPM. Same reason as gotestsum -- the
	// version is recorded in this module's go.sum, verified on download,
	// and bumped by Dependabot, rather than resolving to whatever a
	// workflow's `go install ...@version` happened to name.
	_ "github.com/goreleaser/nfpm/v2/cmd/nfpm"

	// golangci-lint: CI's linter. Built here with the job's own Go rather
	// than downloaded prebuilt: a prebuilt binary cannot read the export
	// data of a newer Go patch release, so every lint job broke the day
	// setup-go picked one up.
	_ "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"

	// gotestsum: CI's test runner, for JUnit output and coverage
	// profiles. Pinned here rather than `go install ...@latest` in a
	// workflow, so the version is recorded in this module's go.sum,
	// verified on download, and bumped by Dependabot under the same
	// cooldown as everything else -- instead of resolving to whatever
	// was published minutes before the job started.
	_ "gotest.tools/gotestsum"
)
