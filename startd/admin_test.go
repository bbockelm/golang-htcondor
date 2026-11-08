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

package startd

import (
	"errors"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

// capability is a syntactically valid administrative capability, shaped
// the way DaemonCore mints one: "admin_<sinful>#<startup>#<seq>" then
// '#', the bracketed session info, and the hex key.
const capability = `admin_<127.0.0.1:9618>#1762500000#3#[Encryption="YES";Integrity="YES";CryptoMethods="AES";ValidCommands="1000,465"]abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789`

func adWith(attrs map[string]any) *classad.ClassAd {
	ad := classad.New()
	for k, v := range attrs {
		_ = ad.Set(k, v)
	}
	return ad
}

// TestNewAdminFromAdImportsTheCapability: the whole point of the
// capability is that it authorizes the command, so an ad that carries
// one must produce an Admin that uses it.
func TestNewAdminFromAdImportsTheCapability(t *testing.T) {
	ad := adWith(map[string]any{
		"MyAddress":         "<127.0.0.1:9618>",
		AdminCapabilityAttr: capability,
	})
	a, err := NewAdminFromAd(ad, true, nil)
	if err != nil {
		t.Fatalf("NewAdminFromAd: %v", err)
	}
	if !a.HasCapability() {
		t.Errorf("Admin did not import the capability")
	}
	if a.Addr() != "<127.0.0.1:9618>" {
		t.Errorf("Addr() = %q, want the ad's MyAddress", a.Addr())
	}
}

// TestNewAdminFromAdWithoutCapability: an ad with no capability is the
// ordinary case on a pool that has remote administration off, or on a
// query that was not authorized to receive private attributes. Which of
// those it was is not visible from here, so the caller decides whether
// falling back to its own credentials is acceptable.
func TestNewAdminFromAdWithoutCapability(t *testing.T) {
	ad := adWith(map[string]any{"MyAddress": "<127.0.0.1:9618>"})

	if _, err := NewAdminFromAd(ad, true, nil); !errors.Is(err, ErrNoAdminCapability) {
		t.Errorf("required capability: err = %v, want ErrNoAdminCapability", err)
	}

	a, err := NewAdminFromAd(ad, false, nil)
	if err != nil {
		t.Fatalf("optional capability: %v", err)
	}
	if a.HasCapability() {
		t.Errorf("Admin claims a capability it was never given")
	}
}

// TestNewAdminFromAdRejectsAnAdWithNoAddress: without MyAddress there is
// nothing to connect to, and the projection that forgets to ask for it
// is the likely cause. Failing is how that gets noticed.
func TestNewAdminFromAdRejectsAnAdWithNoAddress(t *testing.T) {
	ad := adWith(map[string]any{AdminCapabilityAttr: capability})
	if _, err := NewAdminFromAd(ad, false, nil); err == nil {
		t.Errorf("an ad with no MyAddress was accepted")
	}
}

// TestNewAdminFromAdRejectsAnUnusableCapability: a capability that is
// present but will not import must be an error rather than a quiet
// fallback to this process's own credentials. On a pool whose
// authorization lives in the collector, that fallback would refuse
// every command with nothing to say why.
func TestNewAdminFromAdRejectsAnUnusableCapability(t *testing.T) {
	ad := adWith(map[string]any{
		"MyAddress":         "<127.0.0.1:9618>",
		AdminCapabilityAttr: "not-a-capability",
	})
	_, err := NewAdminFromAd(ad, false, nil)
	if err == nil {
		t.Fatalf("a malformed capability was accepted")
	}
	if errors.Is(err, ErrNoAdminCapability) {
		t.Errorf("a malformed capability was reported as an absent one: %v", err)
	}
}

// TestCAResult maps the daemon's Result attribute onto errors. The
// authorization cases are singled out because an access point that may
// no longer administer its execute points goes on planning correctly
// and changing nothing -- the failure worth surfacing.
func TestCAResult(t *testing.T) {
	cases := []struct {
		name    string
		reply   *classad.ClassAd
		wantErr bool
		denied  bool
	}{
		{
			name:  "success",
			reply: adWith(map[string]any{"Result": "Success"}),
		},
		{
			name:    "failure with a reason",
			reply:   adWith(map[string]any{"Result": "Failure", "ErrorString": "no such slot"}),
			wantErr: true,
		},
		{
			name:    "not authorized",
			reply:   adWith(map[string]any{"Result": "NotAuthorized", "ErrorString": "denied"}),
			wantErr: true,
			denied:  true,
		},
		{
			name:    "not authenticated",
			reply:   adWith(map[string]any{"Result": "NotAuthenticated"}),
			wantErr: true,
			denied:  true,
		},
		{
			// A reply with no Result is not something to read
			// optimistically: it means the peer is not what we think.
			name:    "no Result attribute",
			reply:   adWith(map[string]any{"Version": "26.2.0"}),
			wantErr: true,
		},
		{
			name:    "no reply at all",
			reply:   nil,
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := caResult(tc.reply, VerbUpdateMachineAd)
			if (err != nil) != tc.wantErr {
				t.Fatalf("caResult() error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil {
				return
			}
			var ca *CAError
			if errors.As(err, &ca) {
				if ca.Denied() != tc.denied {
					t.Errorf("Denied() = %v, want %v", ca.Denied(), tc.denied)
				}
			} else if tc.denied {
				t.Errorf("want an authorization error, got %T: %v", err, err)
			}
		})
	}
}

// TestCopyAdLeavesTheCallerAlone: sendCA adds three protocol attributes
// to the ad it sends. Adding them to the caller's ad would mean a
// controller that reuses one update ad per tick accumulates them, and
// the startd merges Command into every slot ad it publishes.
func TestCopyAdLeavesTheCallerAlone(t *testing.T) {
	src := adWith(map[string]any{"ReservationDeadline": int64(1762500000)})
	before := strings.Join(src.GetAttributes(), ",")

	cp := copyAd(src)
	_ = cp.Set("Command", VerbUpdateMachineAd)

	if after := strings.Join(src.GetAttributes(), ","); after != before {
		t.Errorf("copyAd's source gained attributes: %q -> %q", before, after)
	}
	if v, ok := cp.EvaluateAttrInt("ReservationDeadline"); !ok || v != 1762500000 {
		t.Errorf("the copy lost the attribute it was made from")
	}
}

// TestVacateClaimRejectsAnEmptySlotName: the startd reads one string and
// looks up a resource by it. An empty name finds nothing and is logged
// and dropped, so it would read as success here.
func TestVacateClaimRejectsAnEmptySlotName(t *testing.T) {
	a := NewAdmin("<127.0.0.1:9618>", nil)
	if err := a.VacateClaim(t.Context(), "   ", false); err == nil {
		t.Errorf("an empty slot name was accepted")
	}
}

// TestCommandNumbers pins the wire integers against HTCondor's
// condor_commands.h. The CA one is the trap: CA_UPDATE_MACHINE_AD is
// 1009, but 1009 never goes on the wire -- it is the name of a verb
// carried inside the request ad, and the command sent is CA_AUTH_CMD.
func TestCommandNumbers(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"CA_AUTH_CMD", CAAuthCmd, 1000},
		{"CA_CMD", CACmd, 1200},
		{"VACATE_CLAIM", cmdVacateClaim, 465},
		{"VACATE_CLAIM_FAST", cmdVacateClaimFast, 475},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}
