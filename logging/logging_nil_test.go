package logging

import "testing"

// A nil *Logger drops lines instead of killing the process.
//
// Callers get one during startup, before the configuration that decides
// the logger's own settings has been read. Every level method routes
// through shouldLog, so this covers all of them -- and it covers them
// one by one rather than trusting that, because a method added later
// could gate somewhere else.
func TestNilLoggerDoesNotPanic(t *testing.T) {
	var l *Logger

	for name, call := range map[string]func(){
		"Error":  func() { l.Error(DestinationGeneral, "msg", "k", "v") },
		"Warn":   func() { l.Warn(DestinationGeneral, "msg", "k", "v") },
		"Info":   func() { l.Info(DestinationGeneral, "msg", "k", "v") },
		"Debug":  func() { l.Debug(DestinationGeneral, "msg", "k", "v") },
		"Errorf": func() { l.Errorf(DestinationGeneral, "msg %d", 1) },
		"Warnf":  func() { l.Warnf(DestinationGeneral, "msg %d", 1) },
		"Infof":  func() { l.Infof(DestinationGeneral, "msg %d", 1) },
		"Debugf": func() { l.Debugf(DestinationGeneral, "msg %d", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("a nil logger panicked: %v", r)
				}
			}()
			call()
		})
	}
}
