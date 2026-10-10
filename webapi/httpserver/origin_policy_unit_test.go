//go:build !integration

package httpserver

import htcondor "github.com/bbockelm/golang-htcondor"

// testOriginPolicy is the unit suite's: refuse unclassified contexts.
const testOriginPolicy = htcondor.UnmarkedDeny
