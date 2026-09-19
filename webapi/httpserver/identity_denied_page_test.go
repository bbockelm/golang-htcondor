// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbockelm/golang-htcondor/idmap"
)

// The person reaching this is in a browser, part-way through an SSO
// redirect. Handing them a JSON object to read is a dead end: they cannot
// act on it and will report the login as broken. The refusal next to this
// one -- group policy -- already renders a page, and these should not
// differ in kind.
func TestIdentityDenialRendersAPageNotJSON(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	rec := httptest.NewRecorder()

	h.renderIdentityDeniedPage(rec, idmap.ErrNoMatch)

	if got := rec.Code; got != 403 {
		t.Errorf("status = %d, want 403", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(strings.ToLower(body), "<html") {
		t.Errorf("body is not an HTML document: %.120s", body)
	}
	if strings.HasPrefix(strings.TrimSpace(body), "{") {
		t.Errorf("body is still a JSON object: %.120s", body)
	}
	// It must still say what went wrong, or the page is prettier and no
	// more useful than the JSON was.
	if !strings.Contains(body, "does not correspond to a local account") {
		t.Errorf("the page does not say why the login was refused: %.200s", body)
	}
}

// The ambiguous case is a configuration fault rather than a missing
// account, and must say so rather than reusing the no-account wording.
func TestIdentityDenialDistinguishesAnAmbiguousMatch(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	rec := httptest.NewRecorder()

	h.renderIdentityDeniedPage(rec, idmap.ErrAmbiguous)

	body := rec.Body.String()
	if !strings.Contains(body, "more than one local account") {
		t.Errorf("an ambiguous match was reported as a missing account: %.200s", body)
	}
}
