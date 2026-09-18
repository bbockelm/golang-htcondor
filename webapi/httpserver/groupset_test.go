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
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestParseGroupList(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"   ", nil},
		{"one", []string{"one"}},
		// Whitespace around names is trimmed: a list written for a human to
		// read should mean what it looks like.
		{"ap2001-login, chtc_staff", []string{"ap2001-login", "chtc_staff"}},
		{"  a ,b ,  c  ", []string{"a", "b", "c"}},
		// A trailing comma is not a group named "".
		{"a,,b,", []string{"a", "b"}},
		{",", nil},
	}
	for _, tc := range cases {
		if got := parseGroupList(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("parseGroupList(%q) = %#v, want %#v", tc.in, got, tc.want)
		}
	}
}

func TestGroupSetAllows(t *testing.T) {
	cases := []struct {
		name     string
		required string
		user     []string
		want     bool
	}{
		// An unconfigured list requires nothing -- these knobs are opt-in,
		// and empty has always meant "no requirement", not "nobody".
		{"unconfigured admits anyone", "", []string{"whatever"}, true},
		{"unconfigured admits a user with no groups", "", nil, true},

		{"single group held", "ap2001-login", []string{"ap2001-login"}, true},
		{"single group not held", "ap2001-login", []string{"chtc_staff"}, false},

		// ANY of the listed groups suffices.
		{"second of two", "ap2001-login, chtc_staff", []string{"chtc_staff"}, true},
		{"first of two", "ap2001-login, chtc_staff", []string{"ap2001-login"}, true},
		{"neither", "ap2001-login, chtc_staff", []string{"other"}, false},
		{"no groups at all", "ap2001-login", nil, false},

		// Case-insensitive, as it was when each was a single group: Unix
		// and directory-sourced names do not reliably agree on case.
		{"case-insensitive", "CHTC_Staff", []string{"chtc_staff"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := newGroupSet(tc.required).allows(tc.user); got != tc.want {
				t.Errorf("allows(%v) with %q = %v, want %v", tc.user, tc.required, got, tc.want)
			}
		})
	}
}

// A reconfigure replaces the list from another goroutine while requests
// read it. Run under -race, this is the check that the swap is safe.
func TestGroupSetIsSafeUnderConcurrentReload(t *testing.T) {
	g := newGroupSet("initial")

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					// Any consistent answer is fine; a torn read is not.
					_ = g.allows([]string{"initial", "replacement"})
					_ = g.String()
				}
			}
		}()
	}
	for i := range 200 {
		if i%2 == 0 {
			g.set("initial")
		} else {
			g.set("replacement, other")
		}
	}
	close(stop)
	wg.Wait()

	g.set("final")
	if !g.allows([]string{"final"}) {
		t.Error("the last write did not take effect")
	}
}

// The web interface and MCP are separate grants. They were one knob, so
// granting somebody the browser necessarily granted them MCP.
func TestWebUIAccessIsSeparateFromMCP(t *testing.T) {
	h := &Handler{
		mcpAccessGroups:   newGroupSet("ap2001-login"),
		webuiAccessGroups: newGroupSet("chtc_staff"),
	}

	staff := []string{"chtc_staff"}
	if err := h.validateWebUIAccess(staff); err != nil {
		t.Errorf("web UI refused a member of its own group: %v", err)
	}
	if err := h.validateGroupAccess(staff); err == nil {
		t.Error("MCP admitted somebody who is only in the web UI group")
	}

	login := []string{"ap2001-login"}
	if err := h.validateGroupAccess(login); err != nil {
		t.Errorf("MCP refused a member of its own group: %v", err)
	}
	if err := h.validateWebUIAccess(login); err == nil {
		t.Error("web UI admitted somebody who is only in the MCP group")
	}
}

// Separating the knobs must not open a deployment that was using the MCP
// group to gate the browser -- which is what that knob did before.
func TestWebUIFallsBackToTheMCPGroup(t *testing.T) {
	h := &Handler{
		mcpAccessGroups:   newGroupSet("ap2001-login"),
		webuiAccessGroups: newGroupSet(""),
	}

	if err := h.validateWebUIAccess([]string{"ap2001-login"}); err != nil {
		t.Errorf("fallback refused a member of the MCP group: %v", err)
	}
	if err := h.validateWebUIAccess([]string{"someone-else"}); err == nil {
		t.Error("with no web UI group configured the browser was left ungated")
	}
}

// The denial a browser receives must be a page, not the API's JSON body:
// the person reaching it authenticated successfully and needs to know it
// was this deployment's policy that turned them away.
func TestBrowserDenialRendersAPage(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	rec := httptest.NewRecorder()

	h.renderAccessDeniedPage(rec, newGroupSet("ap2001-login, chtc_staff"))

	if rec.Code != 403 {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want HTML", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Error("body is not an HTML document")
	}
	// It must name the groups to ask for, or the user has nothing to act on.
	for _, want := range []string{"ap2001-login", "chtc_staff"} {
		if !strings.Contains(body, want) {
			t.Errorf("page does not name the required group %q", want)
		}
	}
}

// With no groups configured the page still has to say something useful.
func TestBrowserDenialWithNoGroupsConfigured(t *testing.T) {
	h := &Handler{logger: testLogger(t)}
	rec := httptest.NewRecorder()
	h.renderAccessDeniedPage(rec, newGroupSet(""))
	if !strings.Contains(rec.Body.String(), "administrator") {
		t.Error("page gives the user nothing to do next")
	}
}

// The access groups must be applied even with MCP disabled.
//
// They used to be assigned inside "if cfg.EnableMCP" while the login path
// that reads them runs whenever the internal IDP is configured. With MCP
// off the list was empty, and an empty list admits everyone -- so a
// deployment that had asked for a group got no gate at all.
func TestAccessGroupsApplyWithoutMCP(t *testing.T) {
	h := newClaimTestHandler(t, HandlerConfig{
		EnableMCP:       false,
		MCPAccessGroup:  "ap2001-login",
		WebUIAdminGroup: "chtc_staff",
	})

	if !h.mcpAccessGroups.configured() {
		t.Error("access group was dropped because MCP is disabled; the login path would admit everyone")
	}
	if err := h.validateGroupAccess([]string{"nobody-in-particular"}); err == nil {
		t.Error("a user outside the configured group was admitted")
	}
	if !h.webuiAdminGroups.configured() {
		t.Error("admin group was dropped because MCP is disabled")
	}
}

// The setters a SIGHUP calls must actually change what the checks see.
func TestReconfigureSettersTakeEffect(t *testing.T) {
	h := &Handler{
		logger:            testLogger(t),
		mcpAccessGroups:   newGroupSet("old-group"),
		webuiAccessGroups: newGroupSet(""),
		webuiAdminGroups:  newGroupSet("old-admins"),
		superuserGroups:   newGroupSet(""),
	}

	if err := h.validateGroupAccess([]string{"new-group"}); err == nil {
		t.Fatal("precondition: new-group should not be admitted yet")
	}

	h.SetMCPAccessGroups("new-group, another")
	if err := h.validateGroupAccess([]string{"another"}); err != nil {
		t.Errorf("reconfigured MCP group did not take effect: %v", err)
	}
	if err := h.validateGroupAccess([]string{"old-group"}); err == nil {
		t.Error("the replaced group still admits; the list was appended to rather than replaced")
	}

	// Web UI was falling back to MCP; giving it its own list must detach it.
	h.SetWebUIAccessGroups("web-only")
	if err := h.validateWebUIAccess([]string{"web-only"}); err != nil {
		t.Errorf("reconfigured web UI group did not take effect: %v", err)
	}
	if err := h.validateWebUIAccess([]string{"another"}); err == nil {
		t.Error("web UI still honours the MCP list after being given its own")
	}

	// Emptying it restores the fallback.
	h.SetWebUIAccessGroups("")
	if err := h.validateWebUIAccess([]string{"another"}); err != nil {
		t.Errorf("emptying the web UI group did not restore the MCP fallback: %v", err)
	}

	h.SetWebUIAdminGroups("new-admins")
	if !h.webuiAdminGroups.allows([]string{"new-admins"}) {
		t.Error("reconfigured admin group did not take effect")
	}
	h.SetWebUIAdminGroups("")
	if h.webuiAdminGroups.configured() {
		t.Error("emptying the admin group should disable the admin UI")
	}
}
