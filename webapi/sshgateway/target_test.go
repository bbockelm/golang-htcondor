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

import "testing"

func TestParseTargetJobIDs(t *testing.T) {
	for _, tc := range []struct {
		in            string
		cluster, proc int
	}{
		{"12345.0", 12345, 0},
		{"12345.7", 12345, 7},
		{"12345", 12345, 0},
		{"0.0", 0, 0},
	} {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseTarget(tc.in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !got.IsJob() {
				t.Fatalf("%q parsed as %v, want a job", tc.in, got)
			}
			if got.Cluster != tc.cluster || got.Proc != tc.proc {
				t.Errorf("= %d.%d, want %d.%d", got.Cluster, got.Proc, tc.cluster, tc.proc)
			}
		})
	}
}

func TestParseTargetSessionNames(t *testing.T) {
	for _, in := range []string{"work", "build-2", "my.session", "a_b"} {
		t.Run(in, func(t *testing.T) {
			got, err := ParseTarget(in)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got.IsJob() {
				t.Fatalf("%q parsed as a job", in)
			}
			if got.Name != in {
				t.Errorf("name = %q, want %q", got.Name, in)
			}
		})
	}
}

// Atoi accepts things a job id never contains. A signed or padded
// number must not become a cluster, because it would silently reach a
// different job than the one the text names.
func TestParseTargetRejectsNumbersThatAreNotJobIDs(t *testing.T) {
	for _, in := range []string{"+5", "-5", "5 ", " 5", "5.+0", "5.-1", "0x10"} {
		t.Run(in, func(t *testing.T) {
			got, err := ParseTarget(in)
			if err == nil && got.IsJob() {
				t.Fatalf("%q parsed as job %d.%d", in, got.Cluster, got.Proc)
			}
		})
	}
}

func TestParseTargetRejectsUnusableNames(t *testing.T) {
	for _, in := range []string{"", "   ", "-leading", "has space", "has/slash", "has:colon"} {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseTarget(in); err == nil {
				t.Fatalf("%q was accepted", in)
			}
		})
	}
}
