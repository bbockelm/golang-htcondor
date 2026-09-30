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

package sshgateway

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuf is a writer the progress display can be pointed at.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// How long the wait took survives the spinner being erased.
//
// The motion does not belong in a scrollback, but the duration does:
// it answers "was that slow?" for somebody who looked away, and it
// survives a copy-paste into a bug report.
func TestElapsedTimeSurvivesTheSpinner(t *testing.T) {
	tty, plain := &syncBuf{}, &syncBuf{}
	pty := make(chan struct{})
	close(pty) // a terminal, so the spinner path runs

	p := newProgress(tty, plain, pty)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.run(ctx)

	p.report("Session \"work\" (job 5.0) is idle")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(tty.String(), "is idle") {
		time.Sleep(10 * time.Millisecond)
	}
	p.stop("")

	out := tty.String()
	if !strings.Contains(out, "Ready after ") {
		t.Errorf("the elapsed time was not kept:\n%q", out)
	}
	// The spinner line itself is erased before it.
	if !strings.Contains(out, "\r\x1b[KReady after ") {
		t.Errorf("the spinner was not cleared before the summary:\n%q", out)
	}
}

// Reaching a job that is already running takes no measurable time, and
// "Ready after 0:00" on every single connection is noise.
func TestNoSummaryWhenThereWasNoWait(t *testing.T) {
	tty, plain := &syncBuf{}, &syncBuf{}
	p := newProgress(tty, plain, make(chan struct{}))
	p.stop("")

	if got := tty.String() + plain.String(); got != "" {
		t.Errorf("something was printed for a wait that never happened: %q", got)
	}
}

// Without a terminal the summary goes where the statuses went --
// stderr -- and carries no escape sequences.
func TestSummaryWithoutATerminalIsPlain(t *testing.T) {
	tty, plain := &syncBuf{}, &syncBuf{}
	p := newProgress(tty, plain, make(chan struct{})) // never closed: no pty

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.run(ctx)

	p.report("Session \"work\" (job 5.0) is idle")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(plain.String(), "is idle") {
		time.Sleep(10 * time.Millisecond)
	}
	p.stop("")

	out := plain.String()
	if !strings.Contains(out, "Ready after ") {
		t.Errorf("the elapsed time was not kept:\n%q", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("escape sequences reached a pipe:\n%q", out)
	}
	if tty.String() != "" {
		t.Errorf("progress went to stdout with no terminal: %q", tty.String())
	}
}

// Reaching a session that is already running is the common case, and it
// is also when somebody is most likely to be unsure which account they
// are: they typed no username at all. So the summary is printed even
// though there was no wait to report.
func TestTheAccountIsPrintedWithNoWaitOnATerminal(t *testing.T) {
	tty, plain := &syncBuf{}, &syncBuf{}
	pty := make(chan struct{})
	close(pty)

	p := newProgress(tty, plain, pty)
	// No run(): a connection this fast stops the display before the
	// goroutine has chosen a stream, which is exactly the case that
	// printed nothing.
	p.stop(`Connected to session "default" (job 5.0) as tannenba`)

	out := tty.String()
	if !strings.Contains(out, "as tannenba") {
		t.Errorf("the account was not printed: %q", out)
	}
	if strings.Contains(out, "Ready after") {
		t.Errorf("a wait that never happened was reported: %q", out)
	}
	if plain.String() != "" {
		t.Errorf("the summary went to stderr although there is a terminal: %q", plain.String())
	}
}

// Without a terminal the summary is suppressed. That stderr belongs to
// `ssh -T gateway cmd`, to scp and to sftp -- none of which asked who
// they are, and all of which are read by something other than a person.
func TestTheAccountIsNotPrintedWithoutATerminal(t *testing.T) {
	tty, plain := &syncBuf{}, &syncBuf{}
	p := newProgress(tty, plain, make(chan struct{})) // never closed: no pty
	p.stop(`Connected to session "default" (job 5.0) as tannenba`)

	if got := tty.String() + plain.String(); got != "" {
		t.Errorf("a scripted client was told about its account: %q", got)
	}
}
