package main

import (
	"testing"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/logging"
)

func lockoutLogger(t *testing.T) *logging.Logger {
	t.Helper()
	l, err := logging.New(&logging.Config{OutputPath: "stderr"})
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	return l
}

// An unset configuration must still produce an enabled lockout. The
// gateway listens on a public SSH port, and a default of "count
// nothing" would mean nobody is covered unless they went looking.
func TestSSHGatewayLockoutDefaultsToEnabled(t *testing.T) {
	got := loadSSHGatewayLockout(config.NewEmpty(), lockoutLogger(t))
	if got.Disabled {
		t.Fatal("the lockout is off by default")
	}
	// Everything else zero, so the sshgateway package's own defaults
	// apply rather than a second set kept in sync by hand.
	if got.Threshold != 0 || got.Window != 0 || got.BanTime != 0 || len(got.TrustedNetworks) != 0 {
		t.Fatalf("an unset configuration produced %+v", got)
	}
}

func TestSSHGatewayLockoutReadsItsSettings(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("HTTP_API_SSH_GATEWAY_LOCKOUT_THRESHOLD", "6")
	cfg.Set("HTTP_API_SSH_GATEWAY_LOCKOUT_NET_THRESHOLD", "30")
	cfg.Set("HTTP_API_SSH_GATEWAY_LOCKOUT_WINDOW", "20m")
	cfg.Set("HTTP_API_SSH_GATEWAY_LOCKOUT_TIME", "30m")
	cfg.Set("HTTP_API_SSH_GATEWAY_LOCKOUT_MAX_TIME", "12h")
	cfg.Set("HTTP_API_SSH_GATEWAY_LOCKOUT_TRUSTED", "192.0.2.0/24, 2001:db8::/32 198.51.100.7")

	got := loadSSHGatewayLockout(cfg, lockoutLogger(t))
	if got.Threshold != 6 || got.NetThreshold != 30 {
		t.Errorf("thresholds are %d and %d", got.Threshold, got.NetThreshold)
	}
	if got.Window != 20*time.Minute || got.BanTime != 30*time.Minute || got.MaxBanTime != 12*time.Hour {
		t.Errorf("durations are %v, %v, %v", got.Window, got.BanTime, got.MaxBanTime)
	}
	want := []string{"192.0.2.0/24", "2001:db8::/32", "198.51.100.7"}
	if len(got.TrustedNetworks) != len(want) {
		t.Fatalf("trusted networks are %v, want %v", got.TrustedNetworks, want)
	}
	for i := range want {
		if got.TrustedNetworks[i] != want[i] {
			t.Fatalf("trusted networks are %v, want %v", got.TrustedNetworks, want)
		}
	}
}

func TestSSHGatewayLockoutDisable(t *testing.T) {
	for _, raw := range []string{"true", "TRUE", "yes", "1", "on"} {
		cfg := config.NewEmpty()
		cfg.Set("HTTP_API_SSH_GATEWAY_LOCKOUT_DISABLE", raw)
		if !loadSSHGatewayLockout(cfg, lockoutLogger(t)).Disabled {
			t.Errorf("%q did not disable the lockout", raw)
		}
	}
	for _, raw := range []string{"false", "no", "0", "", "maybe"} {
		cfg := config.NewEmpty()
		cfg.Set("HTTP_API_SSH_GATEWAY_LOCKOUT_DISABLE", raw)
		if loadSSHGatewayLockout(cfg, lockoutLogger(t)).Disabled {
			t.Errorf("%q disabled the lockout", raw)
		}
	}
}

func TestSplitConfigList(t *testing.T) {
	cases := map[string][]string{
		"":                     {},
		"a":                    {"a"},
		"a,b":                  {"a", "b"},
		"a, b,  c":             {"a", "b", "c"},
		"a b\tc\nd":            {"a", "b", "c", "d"},
		" , , 10.0.0.0/8 , , ": {"10.0.0.0/8"},
	}
	for raw, want := range cases {
		got := splitConfigList(raw)
		if len(got) != len(want) {
			t.Fatalf("%q split to %v, want %v", raw, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%q split to %v, want %v", raw, got, want)
			}
		}
	}
}
