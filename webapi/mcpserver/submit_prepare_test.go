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

package mcpserver

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// The host's pre-submit preparation has to reach BOTH things here that
// submit jobs: the tools, and the interactive session manager the SSH
// gateway drives.
//
// The manager was the one it did not reach. Sessions are submitted
// through it and never through a tool, so a session created by somebody
// typing `ssh` arrived at an access point that requires OAuth service
// credentials without any, and was held with "Job credentials are not
// available" -- a reason with nothing to do with what they asked for.
func TestTheHostsPreSubmitPreparationReachesEverySubmitPath(t *testing.T) {
	var prepared atomic.Int64
	s, err := NewServer(Config{
		ScheddName: "test",
		// Nothing listens here, so the submit below fails after the
		// preparation has run, which is all this needs.
		ScheddAddr:        "127.0.0.1:1",
		EnsureCredentials: func(context.Context) { prepared.Add(1) },
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.Close)

	if mgr := s.InteractiveManager(); mgr == nil {
		t.Fatal("no interactive manager")
	} else if !mgr.HasBeforeSubmitForTest() {
		t.Error("the interactive session manager was not given the host's pre-submit preparation")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, _, serr := s.submitRemote(ctx, "executable = /bin/true\nqueue\n"); serr == nil {
		t.Fatal("a submit to an address nothing listens on succeeded")
	}
	if got := prepared.Load(); got != 1 {
		t.Errorf("the tool submit path prepared %d times, want 1", got)
	}
}

// A server built without the hook -- the standalone stdio one -- must
// submit exactly as it did before, not panic on a nil func.
func TestNoPreparationHookIsFine(t *testing.T) {
	s, err := NewServer(Config{ScheddName: "test", ScheddAddr: "127.0.0.1:1"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(s.Close)

	// And it says so: a hook that is present but does nothing would
	// report as preparation in place, which is how a host that forgot
	// to supply one goes unnoticed.
	if mgr := s.InteractiveManager(); mgr == nil {
		t.Fatal("no interactive manager")
	} else if mgr.HasBeforeSubmitForTest() {
		t.Error("a server given no preparation claims to have some")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, _, serr := s.submitRemote(ctx, "executable = /bin/true\nqueue\n"); serr == nil {
		t.Fatal("a submit to an address nothing listens on succeeded")
	}
}
