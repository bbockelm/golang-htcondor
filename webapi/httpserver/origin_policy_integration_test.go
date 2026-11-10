//go:build integration

package httpserver

import htcondor "github.com/bbockelm/golang-htcondor"

// testOriginPolicy is the integration build's. Its tests drive the pool
// from test code -- the harness waiting for daemons, setup queries and
// submissions -- as the pool's own operator, on contexts nothing marks, so
// they run under the default the library ships with.
const testOriginPolicy = htcondor.UnmarkedAllow
