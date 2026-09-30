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
	"fmt"
	"io"
	"sync"
	"time"
)

// Spinner frames and cadence. Braille dots because they occupy one
// column in every terminal that can show them, and the fallback is a
// box rather than a line that jumps width.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

const spinnerInterval = 120 * time.Millisecond

// progress reports what is happening while a caller waits for a job.
//
// The reason matters more than the motion. "Idle" for two minutes with
// a spinner is a hang; "Idle, waiting for a slot, 1:12" is a queue,
// which is a thing the person can decide to keep waiting for.
//
// Written to the session channel, which means this can only run once
// the channel has been accepted -- the reason resolution happens after
// Accept rather than before it.
type progress struct {
	// tty is where a spinner goes and plain is where a status line
	// goes. They differ on purpose.
	//
	// With a terminal the spinner goes to the channel's stdout, which
	// is what a client with a pty renders. Without one it goes to
	// STDERR, because stdout belongs to the command: writing progress
	// there puts status lines inside `ssh -T gateway cat file > out`.
	tty     io.Writer
	plain   io.Writer
	pty     <-chan struct{}
	started time.Time

	mu sync.Mutex
	// w is whichever of the two this run settled on, and hasPTY is
	// which one it was. decided records that the choice has been made,
	// because both run and stop may be the one to make it: a wait that
	// ends before run has looked at the pty channel still has something
	// to say, and saying it on the wrong stream is as good as not
	// saying it.
	w       io.Writer
	hasPTY  bool
	decided bool

	status   string
	lastLine string
	drawn    bool
	done     bool
}

func newProgress(tty, plain io.Writer, pty <-chan struct{}) *progress {
	return &progress{tty: tty, plain: plain, w: plain, pty: pty, started: time.Now()}
}

// report sets the status shown. Safe to call from another goroutine,
// and cheap enough to call on every poll.
func (p *progress) report(status string) {
	p.mu.Lock()
	p.status = status
	p.mu.Unlock()
}

// run draws until ctx is done or stop is called.
//
// Two modes, chosen by whether the client asked for a terminal. With
// one, a spinner redraws in place. Without one, each distinct status is
// written once on its own line: a pipe has no cursor to move and
// control characters in it corrupt whatever is reading.
func (p *progress) run(ctx context.Context) {
	hasPTY := false
	select {
	case <-p.pty:
		hasPTY = true
	case <-ctx.Done():
		return
	// A client that asks for no terminal sends exec straight away, so
	// waiting a moment costs a plain client nothing and saves a
	// terminal client from a first line with no spinner.
	case <-time.After(250 * time.Millisecond):
	}

	p.settle(hasPTY)
	// Read the choice back rather than trusting the local: stop may
	// have settled it first, and two writers for one channel would
	// interleave a spinner with the line that ends it.
	hasPTY = p.terminal()

	ticker := time.NewTicker(spinnerInterval)
	defer ticker.Stop()

	frame := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		p.mu.Lock()
		if p.done {
			p.mu.Unlock()
			return
		}
		status := p.status
		p.mu.Unlock()
		if status == "" {
			continue
		}

		if hasPTY {
			line := fmt.Sprintf("%s  %s   %s", spinnerFrames[frame%len(spinnerFrames)], status, elapsed(time.Since(p.started)))
			p.draw(line)
			frame++
			continue
		}
		p.writeOnce(status)
	}
}

// draw rewrites the current line in place.
//
// \r returns to column 0 and \x1b[K erases to the end, so a shorter
// status cannot leave the tail of a longer one behind -- padding with
// spaces would, the moment the terminal is narrower than the line.
func (p *progress) draw(line string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return
	}
	_, _ = fmt.Fprintf(p.w, "\r\x1b[K%s", line)
	p.drawn = true
	p.lastLine = line
}

// writeOnce emits a status the first time it is seen. Without a
// terminal there is nothing to animate, and repeating an unchanged
// status would fill a log.
func (p *progress) writeOnce(status string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done || status == p.lastLine {
		return
	}
	_, _ = fmt.Fprintf(p.w, "%s\r\n", status)
	p.lastLine = status
}

// stop ends the display, clears the line the spinner was using, and
// leaves behind how long the wait actually took.
//
// The elapsed time is kept rather than erased because it is the part
// people want afterwards: it survives a copy-paste into a bug report,
// and it answers "was that slow?" for somebody who looked away. The
// spinner itself is erased -- it is motion, and motion does not belong
// in a scrollback.
//
// connected is what the caller ended up connected to -- which job, and
// as which account -- or empty when the wait failed and there is
// nothing to report. It is worth a line even when there was no wait,
// because on this gateway the SSH username is not an identity: a bare
// `ssh gateway` means "my default session" and the account comes from
// the OAuth2 grant, so nothing the person typed tells them which
// account the session actually runs as.
//
// Otherwise nothing is printed when nothing was ever drawn. Reaching a
// job that is already running takes no measurable time, and "ready
// after 0:00" is noise on every single connection.
func (p *progress) stop(connected string) {
	// run may not have chosen a writer yet, because reaching a session
	// that is already running is faster than the grace period it waits
	// out. A pty-req that has already arrived is enough to decide on.
	select {
	case <-p.pty:
		p.settle(true)
	default:
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done {
		return
	}
	p.done = true

	waited := p.drawn || p.lastLine != ""
	// Without a terminal, only a wait earns a line. The summary would
	// otherwise go to the stderr of `ssh -T gateway cmd`, an scp or an
	// sftp -- none of which asked who they are, and all of which are
	// read by something other than a person.
	if !waited && (connected == "" || !p.hasPTY) {
		return
	}
	// One write, erase included: the channel is a stream somebody is
	// reading as it arrives, and splitting this in two lets a reader
	// see the erase without the line that replaces it.
	erase := ""
	if p.drawn {
		erase = "\r\x1b[K"
	}
	switch {
	case waited && connected != "":
		_, _ = fmt.Fprintf(p.w, "%sReady after %s. %s.\r\n", erase, elapsed(time.Since(p.started)), connected)
	case waited:
		_, _ = fmt.Fprintf(p.w, "%sReady after %s.\r\n", erase, elapsed(time.Since(p.started)))
	default:
		_, _ = fmt.Fprintf(p.w, "%s%s.\r\n", erase, connected)
	}
}

// settle fixes which stream this channel's progress and summary go to.
// First caller wins; later ones are no-ops.
func (p *progress) settle(hasPTY bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.decided {
		return
	}
	p.decided, p.hasPTY = true, hasPTY
	if hasPTY {
		p.w = p.tty
	} else {
		p.w = p.plain
	}
}

// terminal reports the settled answer.
func (p *progress) terminal() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hasPTY
}

// elapsed formats a wait the way a person reads a clock.
func elapsed(d time.Duration) string {
	total := int(d.Seconds())
	return fmt.Sprintf("%d:%02d", total/60, total%60)
}
