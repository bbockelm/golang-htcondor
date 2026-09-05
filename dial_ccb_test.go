package htcondor

import (
	"testing"
	"time"
)

// Asking for streaming must actually get streaming.
//
// Cedar picks the mode from the return address alone: empty means the
// standard dial, where the private daemon connects back and the caller
// must be reachable. A caller that set CCBRequireStreaming did so
// precisely because it is not reachable, so honouring the flag but not
// the intent gives it the one mode it cannot use -- and says nothing,
// because the failure is a connection that never arrives.
func TestDialConfigStreamingDoesNotNeedAReturnAddress(t *testing.T) {
	cfg := dialConfig("<10.0.0.1:9618?ccbid=broker#42>", nil, &DialOptions{
		CCBRequireStreaming: true,
	})

	if !cfg.CCBRequireStreaming {
		t.Error("CCBRequireStreaming was dropped")
	}
	if cfg.CCBReturnAddr == "" {
		t.Fatal("no return address, so cedar will do a reverse-connect dial instead of streaming")
	}
	if cfg.CCBReturnAddr != ccbProxyPlaceholderAddr {
		t.Errorf("return address = %q, want the placeholder %q", cfg.CCBReturnAddr, ccbProxyPlaceholderAddr)
	}
}

// A caller that has a real CCB registration keeps its own address; the
// placeholder is a fallback, not an override.
func TestDialConfigKeepsAnExplicitReturnAddress(t *testing.T) {
	const mine = "<192.0.2.7:9618?ccbid=broker#7>"
	cfg := dialConfig("<10.0.0.1:9618?ccbid=broker#42>", nil, &DialOptions{
		CCBReturnAddr:       mine,
		CCBRequireStreaming: true,
	})

	if cfg.CCBReturnAddr != mine {
		t.Errorf("return address = %q, want the caller's own %q", cfg.CCBReturnAddr, mine)
	}
}

// Without the flag nothing is invented: a reachable caller dialing a
// private daemon still gets the standard reverse-connect mode, which is
// the cheaper path when it works.
func TestDialConfigLeavesTheDefaultAlone(t *testing.T) {
	cfg := dialConfig("<10.0.0.1:9618?ccbid=broker#42>", nil, &DialOptions{})

	if cfg.CCBReturnAddr != "" {
		t.Errorf("return address = %q, want empty so the standard dial is used", cfg.CCBReturnAddr)
	}
	if cfg.CCBRequireStreaming {
		t.Error("streaming was turned on without being asked for")
	}
}

// Nil options must stay equivalent to the plain ConnectAndAuthenticate
// this replaced -- address and security only, with cedar applying its own
// defaults. A stray non-zero here would change every existing caller.
func TestDialConfigNilOptionsMatchesThePlainCall(t *testing.T) {
	cfg := dialConfig("<10.0.0.1:9618>", nil, nil)

	if cfg.Address != "<10.0.0.1:9618>" {
		t.Errorf("address = %q", cfg.Address)
	}
	if cfg.Timeout != time.Duration(0) {
		t.Errorf("timeout = %v, want the zero value so cedar applies its default", cfg.Timeout)
	}
	if cfg.CCBReturnAddr != "" || cfg.CCBRequireStreaming {
		t.Errorf("CCB options set with no options given: addr=%q streaming=%v",
			cfg.CCBReturnAddr, cfg.CCBRequireStreaming)
	}
}
