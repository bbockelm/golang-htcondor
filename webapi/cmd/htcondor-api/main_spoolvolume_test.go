package main

import (
	"testing"

	"github.com/htcondor/golang-htcondor/config"
	"github.com/htcondor/golang-htcondor/webapi/spool"
)

// The upload ceiling can be raised and lowered, but never cleared.
// Zero, negative and unreadable all fall back to "unset", which
// spool.LimitsFor answers with the default -- so no config line turns
// the cap off.
func TestLoadSpoolMaxUploadBytesCannotBeTurnedOff(t *testing.T) {
	cases := map[string]struct {
		value string
		set   bool
		want  int64 // 0 means "unset", i.e. the default applies
	}{
		"unset":         {want: 0},
		"bytes":         {value: "1048576", set: true, want: 1 << 20},
		"megabytes":     {value: "500M", set: true, want: 500 << 20},
		"gigabytes":     {value: "2G", set: true, want: 2 << 30},
		"spaced":        {value: " 2 G ", set: true, want: 2 << 30},
		"empty":         {value: "", set: true, want: 0},
		"zero":          {value: "0", set: true, want: 0},
		"negative":      {value: "-5", set: true, want: 0},
		"unreadable":    {value: "lots", set: true, want: 0},
		"fractional":    {value: "1.5G", set: true, want: 0},
		"overflowing":   {value: "9000000T", set: true, want: 0},
		"trailing junk": {value: "500M please", set: true, want: 0},
	}
	for label, c := range cases {
		t.Run(label, func(t *testing.T) {
			cfg := config.NewEmpty()
			if c.set {
				cfg.Set("HTTP_API_SPOOL_MAX_UPLOAD_BYTES", c.value)
			}
			got := loadSpoolMaxUploadBytes(cfg, ccbTestLogger(t))
			if got != c.want {
				t.Fatalf("loadSpoolMaxUploadBytes(%q) = %d, want %d", c.value, got, c.want)
			}
			// What the server actually enforces is the limit this
			// becomes, so assert on that too: a rejected value must
			// land on the default, never on "no ceiling".
			lim := spool.LimitsFor(got)
			if lim.MaxVolume <= 0 {
				t.Fatalf("%q produced MaxVolume %d; the cap must never be cleared",
					c.value, lim.MaxVolume)
			}
			if c.want == 0 && lim.MaxVolume != spool.DefaultLimits().MaxVolume {
				t.Errorf("%q produced MaxVolume %d, want the default %d",
					c.value, lim.MaxVolume, spool.DefaultLimits().MaxVolume)
			}
		})
	}
}

// The knob's documented default has to be the one the code actually
// uses, or docs/server-config.md is telling operators a different
// number than the server enforces.
func TestDocumentedSpoolDefaultMatchesTheCode(t *testing.T) {
	documented, err := spool.ParseSize("1000M")
	if err != nil {
		t.Fatal(err)
	}
	if got := spool.DefaultLimits().MaxVolume; got != documented {
		t.Errorf("docs/server-config.md says the default is 1000M (%d bytes), "+
			"but spool.DefaultLimits().MaxVolume is %d", documented, got)
	}
}
