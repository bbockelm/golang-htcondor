package httpserver

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

// Which built-in interactive applications this access point offers.
//
// There are three -- JupyterLab, VS Code and a terminal -- and until now
// every installation offered all three, because they were written one at
// a time and each arrived switched on. A site has reasons not to offer
// one: a pool that cannot run containers has no use for the VS Code app,
// a site whose policy forbids interactive shells does not want the
// terminal, and a site that runs its own notebook service does not want
// a second one. Saying so meant editing nothing, because there was
// nothing to edit.
//
// What a disabled app refuses is the CREATION of a session. Everything
// else -- listing, fetching, the proxy and the tunnel, deleting --
// keeps working, so sessions already running drain on their own
// lifetimes instead of being stranded holding slots, and their owners
// can still see and stop them. An operator who needs them gone sooner
// removes the jobs, which is the tool for that and was always going to
// be.
//
// A terminal has three front doors, and the gate below only covers one
// of them. The other two are elsewhere and say so: sshGatewaySession
// refuses to make one for a user who typed `ssh`, and the MCP server
// withdraws interactive_session_start (mcpserver/interactive_offered.go,
// told through mcpserver.Config and SetInteractiveTerminal). A gate on
// one door is a setting that does not mean what it says.
//
// Each flag is atomic, because a reconfigure writes them while requests
// read them, and each is stated NEGATIVELY so that the zero value of
// this struct offers all three. That is not tidiness: a Handler built
// as a literal -- which is how most of this package's tests build one --
// would otherwise offer nothing, and every test that creates a session
// would be refused by a setting nobody set. The configuration fields
// are stated negatively for the same reason, one layer up.
type interactiveApps struct {
	jupyterOff  atomic.Bool
	vscodeOff   atomic.Bool
	terminalOff atomic.Bool
}

// interactiveApp names one of the three, for the gate below and for the
// list /auth/me publishes to the SPA.
type interactiveApp string

const (
	appJupyter  interactiveApp = "jupyter"
	appVSCode   interactiveApp = "vscode"
	appTerminal interactiveApp = "terminal"
)

// interactiveAppParam is the configuration parameter that turns each one
// on or off. Named in the refusal, because the person who can change it
// is usually the one reading the error.
var interactiveAppParam = map[interactiveApp]string{
	appJupyter:  "HTTP_API_INTERACTIVE_JUPYTER",
	appVSCode:   "HTTP_API_INTERACTIVE_VSCODE",
	appTerminal: "HTTP_API_INTERACTIVE_TERMINAL",
}

// interactiveAppTitle is what the app is called in a message to a
// person: the name on its section of the Interactive page, not the
// identifier.
var interactiveAppTitle = map[interactiveApp]string{
	appJupyter:  "JupyterLab sessions",
	appVSCode:   "VS Code sessions",
	appTerminal: "Terminal sessions",
}

// enabled reports whether one app is offered.
//
// An unrecognised app reads as offered, which is the direction that
// cannot break a caller: the three constants below are the only values
// in the package, so a fourth would be a programming error, and the
// gate's job is to refuse what an operator turned off rather than
// whatever it does not recognise.
func (a *interactiveApps) enabled(app interactiveApp) bool {
	switch app {
	case appJupyter:
		return !a.jupyterOff.Load()
	case appVSCode:
		return !a.vscodeOff.Load()
	case appTerminal:
		return !a.terminalOff.Load()
	}
	return true
}

func (a *interactiveApps) set(app interactiveApp, on bool) {
	switch app {
	case appJupyter:
		a.jupyterOff.Store(!on)
	case appVSCode:
		a.vscodeOff.Store(!on)
	case appTerminal:
		a.terminalOff.Store(!on)
	}
}

// offered is the apps this access point offers, in the order the
// Interactive page shows them. Published by /auth/me so the SPA renders
// what exists rather than probing three endpoints to find out, and so
// an empty list can take the navigation item away with it.
//
// Never nil, so that "offers none" serialises as [] rather than null:
// the SPA tells an empty list from a missing field, and they mean
// opposite things. See AuthMeResponse.Interactive.
func (a *interactiveApps) offered() []string {
	out := make([]string, 0, 3)
	for _, app := range []interactiveApp{appJupyter, appVSCode, appTerminal} {
		if a.enabled(app) {
			out = append(out, string(app))
		}
	}
	return out
}

// requireInteractiveApp refuses to start a session in an app this site
// does not offer, and reports whether the caller may continue.
//
// 503 with the parameter named, the way requireReservations refuses:
// this is a statement about the installation and not about the caller,
// and answering 403 would send them looking for a permission they do
// not lack.
func (s *Handler) requireInteractiveApp(w http.ResponseWriter, app interactiveApp) bool {
	if s.interactive.enabled(app) {
		return true
	}
	s.writeError(w, http.StatusServiceUnavailable,
		fmt.Sprintf("%s are not offered by this access point. Set %s = true to enable them.",
			interactiveAppTitle[app], interactiveAppParam[app]))
	return false
}
