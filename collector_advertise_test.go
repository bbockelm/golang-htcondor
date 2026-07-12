package htcondor

import (
	"context"
	"io"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/commands"
	"github.com/bbockelm/cedar/message"
)

// memStream is an in-memory message.StreamInterface used to capture the CEDAR
// frames a send path writes, then replay them to a reader in the same test. It
// records frames on WriteFrame and pops them in order on ReadFrame, which is all
// that is needed for the write-then-read fake-collector pattern.
type memStream struct {
	frames []memFrame
	pos    int
}

type memFrame struct {
	data []byte
	eom  bool
}

func (s *memStream) WriteFrame(_ context.Context, data []byte, isEOM bool) error {
	s.frames = append(s.frames, memFrame{data: append([]byte(nil), data...), eom: isEOM})
	return nil
}

func (s *memStream) ReadFrame(_ context.Context) ([]byte, bool, error) {
	if s.pos >= len(s.frames) {
		return nil, false, io.EOF
	}
	f := s.frames[s.pos]
	s.pos++
	return f.data, f.eom, nil
}

func (s *memStream) IsEncrypted() bool { return false }

// TestPutAdvertiseAds_PublicPrivatePair drives the public+private ad send path a
// STARTD uses and asserts, from the receiver's side, that (1) both ads arrive on
// one message, (2) MyAddress was copied from the public ad into the private ad,
// and (3) a private/secret attribute (ClaimId) in the private ad survives the
// trip (it must NOT be redacted the way it would be for the public ad).
func TestPutAdvertiseAds_PublicPrivatePair(t *testing.T) {
	ctx := context.Background()

	pub := classad.New()
	if err := pub.Set("MyType", "Machine"); err != nil {
		t.Fatalf("set MyType: %v", err)
	}
	if err := pub.Set("Name", "slot1@host.example.edu"); err != nil {
		t.Fatalf("set Name: %v", err)
	}
	if err := pub.Set("MyAddress", "<192.168.1.10:9618>"); err != nil {
		t.Fatalf("set MyAddress: %v", err)
	}
	if err := pub.Set("StartdIpAddr", "<192.168.1.10:9618>"); err != nil {
		t.Fatalf("set StartdIpAddr: %v", err)
	}
	// A secret attribute set on the PUBLIC ad must be redacted on the wire.
	if err := pub.Set("ClaimId", "PUBLIC-SHOULD-BE-STRIPPED"); err != nil {
		t.Fatalf("set public ClaimId: %v", err)
	}

	priv := classad.New()
	if err := priv.Set("MyType", "Machine"); err != nil {
		t.Fatalf("set private MyType: %v", err)
	}
	if err := priv.Set("Name", "slot1@host.example.edu"); err != nil {
		t.Fatalf("set private Name: %v", err)
	}
	if err := priv.Set("ClaimId", "SECRET-CLAIM-12345"); err != nil {
		t.Fatalf("set private ClaimId: %v", err)
	}
	// Intentionally no MyAddress on the private ad; it should be copied in.

	stream := &memStream{}
	msg := message.NewMessageForStream(stream)
	if err := putAdvertiseAds(ctx, msg, pub, priv); err != nil {
		t.Fatalf("putAdvertiseAds: %v", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		t.Fatalf("FinishMessage: %v", err)
	}

	// Receiver side: read the public ad then the private ad off the one message.
	rmsg := message.NewMessageFromStream(stream)

	gotPub, err := rmsg.GetClassAd(ctx)
	if err != nil {
		t.Fatalf("read public ad: %v", err)
	}
	gotPriv, err := rmsg.GetClassAd(ctx)
	if err != nil {
		t.Fatalf("read private ad: %v", err)
	}

	// Public ad basics.
	if name, ok := gotPub.EvaluateAttrString("Name"); !ok || name != "slot1@host.example.edu" {
		t.Errorf("public Name = %q, ok=%v; want slot1@host.example.edu", name, ok)
	}
	if addr, ok := gotPub.EvaluateAttrString("MyAddress"); !ok || addr != "<192.168.1.10:9618>" {
		t.Errorf("public MyAddress = %q, ok=%v; want <192.168.1.10:9618>", addr, ok)
	}
	// The secret attribute on the public ad must have been redacted.
	if _, ok := gotPub.Lookup("ClaimId"); ok {
		t.Error("public ad leaked ClaimId; it should be redacted")
	}

	// Private ad: MyAddress copied in, ClaimId survived, Name present.
	if addr, ok := gotPriv.EvaluateAttrString("MyAddress"); !ok || addr != "<192.168.1.10:9618>" {
		t.Errorf("private MyAddress = %q, ok=%v; want copied <192.168.1.10:9618>", addr, ok)
	}
	if cid, ok := gotPriv.EvaluateAttrString("ClaimId"); !ok || cid != "SECRET-CLAIM-12345" {
		t.Errorf("private ClaimId = %q, ok=%v; want SECRET-CLAIM-12345 (must survive)", cid, ok)
	}
	if name, ok := gotPriv.EvaluateAttrString("Name"); !ok || name != "slot1@host.example.edu" {
		t.Errorf("private Name = %q, ok=%v; want slot1@host.example.edu", name, ok)
	}
}

// TestPutAdvertiseAds_NilPrivateAd verifies a nil private ad sends only the
// public ad (a missing private ad is tolerated) and does not copy anything.
func TestPutAdvertiseAds_NilPrivateAd(t *testing.T) {
	ctx := context.Background()

	pub := classad.New()
	if err := pub.Set("MyType", "Machine"); err != nil {
		t.Fatalf("set MyType: %v", err)
	}
	if err := pub.Set("Name", "slot1@host.example.edu"); err != nil {
		t.Fatalf("set Name: %v", err)
	}
	if err := pub.Set("MyAddress", "<10.0.0.1:9618>"); err != nil {
		t.Fatalf("set MyAddress: %v", err)
	}

	stream := &memStream{}
	msg := message.NewMessageForStream(stream)
	if err := putAdvertiseAds(ctx, msg, pub, nil); err != nil {
		t.Fatalf("putAdvertiseAds: %v", err)
	}
	if err := msg.FinishMessage(ctx); err != nil {
		t.Fatalf("FinishMessage: %v", err)
	}

	rmsg := message.NewMessageFromStream(stream)
	gotPub, err := rmsg.GetClassAd(ctx)
	if err != nil {
		t.Fatalf("read public ad: %v", err)
	}
	if name, ok := gotPub.EvaluateAttrString("Name"); !ok || name != "slot1@host.example.edu" {
		t.Errorf("public Name = %q, ok=%v", name, ok)
	}
	// No second ad should be present.
	if _, err := rmsg.GetClassAd(ctx); err == nil {
		t.Error("expected no second (private) ad, but GetClassAd succeeded")
	}
}

// TestAdvertiseMultiple_RejectsPrivateAd verifies AdvertiseMultiple refuses a
// PrivateAd (it is a single-ad concept) with a clear per-ad error.
func TestAdvertiseMultiple_RejectsPrivateAd(t *testing.T) {
	c := NewCollector("localhost:9618")
	ctx := context.Background()

	ad := classad.New()
	if err := ad.Set("MyType", "Machine"); err != nil {
		t.Fatalf("set MyType: %v", err)
	}
	priv := classad.New()

	errs := c.AdvertiseMultiple(ctx, []*classad.ClassAd{ad, ad}, &AdvertiseOptions{PrivateAd: priv})
	if len(errs) != 2 {
		t.Fatalf("expected 2 errors, got %d", len(errs))
	}
	for i, err := range errs {
		if err == nil {
			t.Errorf("errs[%d] = nil; want a PrivateAd-not-supported error", i)
		}
	}
}

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

			cmd := getCommandForAdvertise(ad)

			if cmd != tt.expected {
				t.Errorf("Expected command %d, got %d", tt.expected, cmd)
			}
		})
	}
}

func TestGetCommandForAdvertise_NoMyType(t *testing.T) {
	ad := classad.New()
	// Don't set MyType

	cmd := getCommandForAdvertise(ad)

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
		name    string
		attrs   map[string]interface{}
		minSize int
		maxSize int
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
				"MyType": "Machine",
				"Name":   "slot1@hostname",
				"State":  "Unclaimed",
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
		// Simulate ApplyDefaults logic
		opts := &AdvertiseOptions{}
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
