package httpserver

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func offeringHandler(jupyter, vscode, terminal bool) *Handler {
	h := &Handler{}
	h.interactive.set(appJupyter, jupyter)
	h.interactive.set(appVSCode, vscode)
	h.interactive.set(appTerminal, terminal)
	return h
}

// What the SPA reads: the apps this access point offers, in the order
// the Interactive page shows them.
func TestOfferedListsTheAppsInPageOrder(t *testing.T) {
	h := offeringHandler(true, false, true)
	if got, want := h.interactive.offered(), []string{"jupyter", "terminal"}; !slices.Equal(got, want) {
		t.Errorf("offered = %v, want %v", got, want)
	}
	// Empty rather than nil-with-a-placeholder: this is what takes the
	// Interactive item out of the navigation.
	if got := offeringHandler(false, false, false).interactive.offered(); len(got) != 0 {
		t.Errorf("offered = %v, want nothing", got)
	}
}

// Creating a session in an app the site does not offer is refused, and
// the refusal says which setting decided it -- the person who can
// change it is usually the one reading the error.
func TestCreatingInADisabledAppIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		path   string
		app    interactiveApp
		param  string
		handle func(*Handler, http.ResponseWriter, *http.Request)
	}{
		{
			name:   "jupyter",
			path:   "/api/v1/jupyter/instances",
			app:    appJupyter,
			param:  "HTTP_API_INTERACTIVE_JUPYTER",
			handle: (*Handler).handleJupyterPath,
		},
		{
			name:   "vscode",
			path:   "/api/v1/apps",
			app:    appVSCode,
			param:  "HTTP_API_INTERACTIVE_VSCODE",
			handle: (*Handler).handleAppsPath,
		},
		{
			name:   "terminal",
			path:   "/api/v1/interactive/terminal",
			app:    appTerminal,
			param:  "HTTP_API_INTERACTIVE_TERMINAL",
			handle: (*Handler).handleInteractiveTerminal,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := offeringHandler(true, true, true)
			h.interactive.set(tc.app, false)

			w := httptest.NewRecorder()
			tc.handle(h, w, httptest.NewRequest(http.MethodPost, tc.path, nil))

			// 503 and not 403: this is a statement about the
			// installation, not about the caller, and 403 would send
			// them looking for a permission they do not lack.
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
			}
			if !strings.Contains(w.Body.String(), tc.param) {
				t.Errorf("body does not name the setting: %s", w.Body.String())
			}
		})
	}
}

// The gate must refuse the app it names and nothing else: turning off
// VS Code cannot take notebooks with it.
func TestDisablingOneAppLeavesTheOthers(t *testing.T) {
	h := offeringHandler(true, false, true)

	w := httptest.NewRecorder()
	h.handleAppsPath(w, httptest.NewRequest(http.MethodPost, "/api/v1/apps", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("VS Code was not refused: status = %d", w.Code)
	}

	// The other two get past the gate. They then fail on authentication,
	// which is the point: the gate is not what stopped them.
	for _, tc := range []struct {
		name string
		path string
		fn   func(*Handler, http.ResponseWriter, *http.Request)
	}{
		{"jupyter", "/api/v1/jupyter/instances", (*Handler).handleJupyterPath},
		{"terminal", "/api/v1/interactive/terminal", (*Handler).handleInteractiveTerminal},
	} {
		w := httptest.NewRecorder()
		tc.fn(h, w, httptest.NewRequest(http.MethodPost, tc.path, nil))
		if w.Code == http.StatusServiceUnavailable {
			t.Errorf("%s was refused by the gate: %s", tc.name, w.Body.String())
		}
	}
}

// Only creation is refused. Listing keeps working so a session already
// running can still be found and stopped, instead of being stranded
// holding a slot.
func TestDisablingAnAppStillListsItsSessions(t *testing.T) {
	h := offeringHandler(false, false, false)
	for _, tc := range []struct {
		name string
		path string
		fn   func(*Handler, http.ResponseWriter, *http.Request)
	}{
		{"jupyter", "/api/v1/jupyter/instances", (*Handler).handleJupyterPath},
		{"vscode", "/api/v1/apps", (*Handler).handleAppsPath},
		{"terminal", "/api/v1/interactive/terminal", (*Handler).handleInteractiveTerminal},
	} {
		w := httptest.NewRecorder()
		tc.fn(h, w, httptest.NewRequest(http.MethodGet, tc.path, nil))
		if w.Code == http.StatusServiceUnavailable {
			t.Errorf("listing %s sessions was refused: %s", tc.name, w.Body.String())
		}
	}
}

// A reconfigure reaches the next launch. Restarting the daemon to stop
// new notebooks being made would drop every notebook already running.
func TestInteractiveAppsFollowReconfigure(t *testing.T) {
	h := offeringHandler(true, true, true)

	h.SetInteractiveJupyter("false")
	if h.interactive.enabled(appJupyter) {
		t.Error("JupyterLab survived a reconfigure that turned it off")
	}
	h.SetInteractiveJupyter("true")
	if !h.interactive.enabled(appJupyter) {
		t.Error("turning JupyterLab back on did not take")
	}

	// Default true on an empty or unparseable value: these have always
	// been served, and an operator who mistyped is told in the log
	// rather than having their users lose the app.
	h.SetInteractiveVSCode("")
	if !h.interactive.enabled(appVSCode) {
		t.Error("an empty value turned VS Code off; the default is on")
	}
}

// A Handler built as a literal offers all three, which is how most of
// this package's tests build one -- and how an installation that has
// never heard of these settings behaves.
//
// Pinned as a test because the zero value is the entire reason the
// flags are stored negatively: written the obvious way round, every
// test that creates a session is refused by a setting nobody set, and
// every site that upgrades loses three features on restart.
func TestAZeroHandlerOffersEveryApp(t *testing.T) {
	var h Handler
	for _, app := range []interactiveApp{appJupyter, appVSCode, appTerminal} {
		if !h.interactive.enabled(app) {
			t.Errorf("%s is not offered by a Handler nobody configured", app)
		}
	}
	if got, want := h.interactive.offered(), []string{"jupyter", "vscode", "terminal"}; !slices.Equal(got, want) {
		t.Errorf("offered = %v, want %v", got, want)
	}
}
