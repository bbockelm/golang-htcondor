package htcondor

import (
	"context"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
)

func TestGetCommandForAdvertise(t *testing.T) {
	tests := []struct {
		name     string
		myType   string
		expected commands.CommandType
	}{
		{
			name:     "Startd ad",
			myType:   "Machine",
			expected: commands.UPDATE_STARTD_AD,
		},
		{
			name:     "Startd ad lowercase",
			myType:   "startd",
			expected: commands.UPDATE_STARTD_AD,
		},
		{
			name:     "Schedd ad",
			myType:   "Scheduler",
			expected: commands.UPDATE_SCHEDD_AD,
		},
		{
			name:     "Schedd ad alternate",
			myType:   "Schedd",
			expected: commands.UPDATE_SCHEDD_AD,
		},
		{
			name:     "Master ad",
			myType:   "DaemonMaster",
			expected: commands.UPDATE_MASTER_AD,
		},
		{
			name:     "Master ad alternate",
			myType:   "Master",
			expected: commands.UPDATE_MASTER_AD,
		},
		{
			name:     "Submitter ad",
			myType:   "Submitter",
			expected: commands.UPDATE_SUBMITTOR_AD,
		},
		{
			name:     "Collector ad",
			myType:   "Collector",
			expected: commands.UPDATE_COLLECTOR_AD,
		},
		{
			name:     "Negotiator ad",
			myType:   "Negotiator",
			expected: commands.UPDATE_NEGOTIATOR_AD,
		},
		{
			name:     "License ad",
			myType:   "License",
			expected: commands.UPDATE_LICENSE_AD,
		},
		{
			name:     "Storage ad",
			myType:   "Storage",
			expected: commands.UPDATE_STORAGE_AD,
		},
		{
			name:     "Accounting ad",
			myType:   "Accounting",
			expected: commands.UPDATE_ACCOUNTING_AD,
		},
		{
			name:     "Grid ad",
			myType:   "Grid",
			expected: commands.UPDATE_GRID_AD,
		},
		{
			name:     "HAD ad",
			myType:   "HAD",
			expected: commands.UPDATE_HAD_AD,
		},
		{
			name:     "Generic ad",
			myType:   "Generic",
			expected: commands.UPDATE_AD_GENERIC,
		},
		{
			name:     "Unknown type defaults to generic",
			myType:   "UnknownType",
			expected: commands.UPDATE_AD_GENERIC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad := classad.New()
			if err := ad.Set("MyType", tt.myType); err != nil {
				t.Fatalf("Failed to set MyType: %v", err)
			}

			cmd, err := getCommandForAdvertise(ad)
			if err != nil {
				t.Fatalf("getCommandForAdvertise failed: %v", err)
			}

			if cmd != tt.expected {
				t.Errorf("Expected command %d, got %d", tt.expected, cmd)
			}
		})
	}
}

func TestGetCommandForAdvertise_NoMyType(t *testing.T) {
	ad := classad.New()
	// Don't set MyType

	cmd, err := getCommandForAdvertise(ad)
	if err != nil {
		t.Fatalf("getCommandForAdvertise failed: %v", err)
	}

	if cmd != commands.UPDATE_AD_GENERIC {
		t.Errorf("Expected UPDATE_AD_GENERIC for ad without MyType, got %d", cmd)
	}
}

func TestEnsureMyAddress(t *testing.T) {
	t.Run("MyAddress already set", func(t *testing.T) {
		ad := classad.New()
		expectedAddr := "<192.168.1.1:9618>"
		if err := ad.Set("MyAddress", expectedAddr); err != nil {
			t.Fatalf("Failed to set MyAddress: %v", err)
		}

		err := ensureMyAddress(ad)
		if err != nil {
			t.Fatalf("ensureMyAddress failed: %v", err)
		}

		addr, ok := ad.EvaluateAttrString("MyAddress")
		if !ok {
			t.Fatal("MyAddress not found in ad")
		}

		if addr != expectedAddr {
			t.Errorf("Expected MyAddress %s, got %s", expectedAddr, addr)
		}
	})

	t.Run("MyAddress not set - gets default", func(t *testing.T) {
		ad := classad.New()

		err := ensureMyAddress(ad)
		if err != nil {
			t.Fatalf("ensureMyAddress failed: %v", err)
		}

		addr, ok := ad.EvaluateAttrString("MyAddress")
		if !ok {
			t.Fatal("MyAddress not found in ad after ensureMyAddress")
		}

		if addr != "<127.0.0.1:0>" {
			t.Errorf("Expected default MyAddress <127.0.0.1:0>, got %s", addr)
		}
	})
}

func TestEstimateClassAdSize(t *testing.T) {
	tests := []struct {
		name     string
		attrs    map[string]interface{}
		minSize  int
		maxSize  int
	}{
		{
			name:    "Empty ad",
			attrs:   map[string]interface{}{},
			minSize: 0,
			maxSize: 10,
		},
		{
			name: "Small ad",
			attrs: map[string]interface{}{
				"MyType":    "Machine",
				"Name":      "slot1@hostname",
				"State":     "Unclaimed",
			},
			minSize: 200,
			maxSize: 500,
		},
		{
			name: "Large ad",
			attrs: map[string]interface{}{
				"MyType":       "Machine",
				"Name":         "slot1@hostname.domain.edu",
				"State":        "Unclaimed",
				"Activity":     "Idle",
				"Memory":       8192,
				"Cpus":         4,
				"Disk":         100000,
				"TotalSlots":   10,
				"Requirements": "TARGET.Arch == \"X86_64\"",
				"Rank":         "TARGET.Memory",
			},
			minSize: 800,
			maxSize: 1200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ad := classad.New()
			for k, v := range tt.attrs {
				if err := ad.Set(k, v); err != nil {
					t.Fatalf("Failed to set %s: %v", k, err)
				}
			}

			size := estimateClassAdSize(ad)

			if size < tt.minSize || size > tt.maxSize {
				t.Errorf("Expected size between %d and %d, got %d", tt.minSize, tt.maxSize, size)
			}
		})
	}
}

func TestAdvertiseOptions_Defaults(t *testing.T) {
	t.Run("Nil options", func(t *testing.T) {
		var opts *AdvertiseOptions
		if opts == nil {
			opts = &AdvertiseOptions{}
		}
		if !opts.WithAck && !opts.UseTCP {
			opts.UseTCP = true
		}
		if opts.WithAck {
			opts.UseTCP = true
		}

		if !opts.UseTCP {
			t.Error("Expected UseTCP to be true by default")
		}
	})

	t.Run("WithAck forces TCP", func(t *testing.T) {
		opts := &AdvertiseOptions{
			WithAck: true,
			UseTCP:  false,
		}
		if opts.WithAck {
			opts.UseTCP = true
		}

		if !opts.UseTCP {
			t.Error("Expected WithAck to force UseTCP to true")
		}
	})
}

func TestAdvertise_NilAd(t *testing.T) {
	collector := NewCollector("localhost:9618")
	ctx := context.Background()

	err := collector.Advertise(ctx, nil, nil)
	if err == nil {
		t.Error("Expected error for nil ad, got nil")
	}
}

func TestAdvertiseMultiple_EmptySlice(t *testing.T) {
	collector := NewCollector("localhost:9618")
	ctx := context.Background()

	errors := collector.AdvertiseMultiple(ctx, []*classad.ClassAd{}, nil)
	if errors != nil {
		t.Errorf("Expected nil errors for empty slice, got %v", errors)
	}
}
