package htcondor

import (
	"testing"
	"time"
)

const privCCBAddr = "<192.0.2.9:9618?PrivNet=pool-a&PrivAddr=<10.0.0.9:9618>&ccbid=192.0.2.1:9618%23123>"

func privDialer(t *testing.T, ourNet string) *CCBDialer {
	t.Helper()
	d := NewCCBDialer(CCBDialerConfig{PrivateNetworkName: ourNet})
	if d == nil {
		t.Fatal("NewCCBDialer returned nil")
	}
	return d
}

// The point of the feature: a matching network is dialed directly, so
// nothing has to listen inbound and nothing depends on the broker's version.
func TestDialerPrefersThePrivateAddress(t *testing.T) {
	d := privDialer(t, "pool-a")
	got, matched := d.privateRewrite(privCCBAddr)
	if !matched {
		t.Fatal("a matching private network was not used")
	}
	if got == privCCBAddr {
		t.Error("the address was not rewritten")
	}
}

// A private network can be partly reachable, and a client that gave up
// there would have no route to the daemon at all -- the broker still works.
// So a failure is remembered rather than fatal, and the next dial goes
// straight to the broker instead of paying the timeout again.
func TestPrivateFailureIsRememberedThenExpires(t *testing.T) {
	d := privDialer(t, "pool-a")
	now := time.Unix(1_700_000_000, 0)
	d.now = func() time.Time { return now }

	if _, matched := d.privateRewrite(privCCBAddr); !matched {
		t.Fatal("expected the first dial to try the private address")
	}
	d.recordPrivate(privCCBAddr, errDialFailed{})

	if _, matched := d.privateRewrite(privCCBAddr); matched {
		t.Error("the private address was tried again straight after it failed")
	}

	// It is a network that might come back, not one written off for the
	// life of the process.
	now = now.Add(d.ttl + time.Second)
	if _, matched := d.privateRewrite(privCCBAddr); !matched {
		t.Error("the private network was never retried after the TTL")
	}
}

// A success clears the memory, so one blip does not keep steering dials to
// the broker for a TTL after the network is back.
func TestPrivateSuccessClearsTheMemory(t *testing.T) {
	d := privDialer(t, "pool-a")
	d.recordPrivate(privCCBAddr, errDialFailed{})
	if _, matched := d.privateRewrite(privCCBAddr); matched {
		t.Fatal("expected the failure to be remembered")
	}
	d.recordPrivate(privCCBAddr, nil)
	if _, matched := d.privateRewrite(privCCBAddr); !matched {
		t.Error("a success did not clear the remembered failure")
	}
}

// An unset PRIVATE_NETWORK_NAME must change nothing: that is every existing
// deployment, and they go through the broker exactly as before.
func TestNoPrivateNetworkConfiguredChangesNothing(t *testing.T) {
	d := privDialer(t, "")
	if got, matched := d.privateRewrite(privCCBAddr); matched || got != privCCBAddr {
		t.Errorf("an unconfigured client rewrote the address: matched=%v got=%q", matched, got)
	}
}

// A nil dialer is a supported caller -- one that configured none of this --
// and must not panic on the new path.
func TestNilDialerPrivateRewrite(t *testing.T) {
	var d *CCBDialer
	if got, matched := d.privateRewrite(privCCBAddr); matched || got != privCCBAddr {
		t.Errorf("nil dialer rewrote the address: matched=%v got=%q", matched, got)
	}
	d.recordPrivate(privCCBAddr, nil) // must not panic
}

type errDialFailed struct{}

func (errDialFailed) Error() string { return "dial failed" }
