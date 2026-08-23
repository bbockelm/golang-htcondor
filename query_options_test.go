package htcondor

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestQueryOptionsApplyDefaults(t *testing.T) {
	tests := []struct {
		name      string
		opts      QueryOptions
		wantLimit int
	}{
		{
			name:      "empty options gets default limit",
			opts:      QueryOptions{},
			wantLimit: 50,
		},
		{
			name:      "custom limit preserved",
			opts:      QueryOptions{Limit: 100},
			wantLimit: 100,
		},
		{
			name:      "negative limit (unlimited) preserved",
			opts:      QueryOptions{Limit: -1},
			wantLimit: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.opts.ApplyDefaults()
			if got.Limit != tt.wantLimit {
				t.Errorf("ApplyDefaults() limit = %v, want %v", got.Limit, tt.wantLimit)
			}
		})
	}
}

func TestQueryOptionsIsUnlimited(t *testing.T) {
	tests := []struct {
		name string
		opts QueryOptions
		want bool
	}{
		{
			name: "default limit is not unlimited",
			opts: QueryOptions{Limit: 50},
			want: false,
		},
		{
			name: "negative limit is unlimited",
			opts: QueryOptions{Limit: -1},
			want: true,
		},
		{
			name: "zero is not unlimited",
			opts: QueryOptions{Limit: 0},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.IsUnlimited(); got != tt.want {
				t.Errorf("IsUnlimited() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryOptionsShouldUseAllAttributes(t *testing.T) {
	tests := []struct {
		name string
		opts QueryOptions
		want bool
	}{
		{
			name: "empty projection returns false",
			opts: QueryOptions{},
			want: false,
		},
		{
			name: "star projection returns true",
			opts: QueryOptions{Projection: []string{"*"}},
			want: true,
		},
		{
			name: "multiple attributes returns false",
			opts: QueryOptions{Projection: []string{"ClusterId", "ProcId"}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.opts.ShouldUseAllAttributes(); got != tt.want {
				t.Errorf("ShouldUseAllAttributes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestQueryOptionsGetEffectiveProjection(t *testing.T) {
	defaultProj := []string{"ClusterId", "ProcId", "Owner"}

	tests := []struct {
		name string
		opts QueryOptions
		want []string
	}{
		{
			name: "empty projection uses default",
			opts: QueryOptions{},
			want: defaultProj,
		},
		{
			name: "star projection returns nil for all attributes",
			opts: QueryOptions{Projection: []string{"*"}},
			want: nil,
		},
		{
			name: "custom projection preserved",
			opts: QueryOptions{Projection: []string{"JobStatus", "Cmd"}},
			want: []string{"JobStatus", "Cmd"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.opts.GetEffectiveProjection(defaultProj)
			if len(got) != len(tt.want) {
				t.Errorf("GetEffectiveProjection() length = %v, want %v", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("GetEffectiveProjection()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestDefaultJobProjection(t *testing.T) {
	proj := DefaultJobProjection()

	// Should return a non-empty slice
	if len(proj) == 0 {
		t.Error("DefaultJobProjection() returned empty slice")
	}

	// Should contain common job attributes
	expectedAttrs := []string{"ClusterId", "ProcId", "Owner", "JobStatus"}
	for _, attr := range expectedAttrs {
		found := false
		for _, p := range proj {
			if p == attr {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultJobProjection() missing expected attribute: %s", attr)
		}
	}
}

func TestDefaultCollectorProjection(t *testing.T) {
	proj := DefaultCollectorProjection()

	// Should return a non-empty slice
	if len(proj) == 0 {
		t.Error("DefaultCollectorProjection() returned empty slice")
	}

	// Should contain common collector attributes
	expectedAttrs := []string{"Name", "Machine", "MyType"}
	for _, attr := range expectedAttrs {
		found := false
		for _, p := range proj {
			if p == attr {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DefaultCollectorProjection() missing expected attribute: %s", attr)
		}
	}
}

func TestEncodeDecodePageToken(t *testing.T) {
	tests := []struct {
		name      string
		clusterID int64
		procID    int64
	}{
		{
			name:      "simple job ID",
			clusterID: 123,
			procID:    0,
		},
		{
			name:      "job with proc",
			clusterID: 456,
			procID:    7,
		},
		{
			name:      "large cluster ID",
			clusterID: 999999,
			procID:    42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := EncodePageToken(tt.clusterID, tt.procID)
			if token == "" {
				t.Error("EncodePageToken() returned empty string")
			}

			gotCluster, gotProc, err := DecodePageToken(token)
			if err != nil {
				t.Errorf("DecodePageToken() error = %v", err)
			}
			if gotCluster != tt.clusterID {
				t.Errorf("DecodePageToken() clusterID = %v, want %v", gotCluster, tt.clusterID)
			}
			if gotProc != tt.procID {
				t.Errorf("DecodePageToken() procID = %v, want %v", gotProc, tt.procID)
			}
		})
	}
}

func TestDecodePageTokenErrors(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "empty token",
			token: "",
		},
		{ //nolint:gosec // G101: test data, not credentials
			name:  "invalid base64",
			token: "not-valid-base64!@#",
		},
		{
			name:  "invalid job ID format - no dot",
			token: base64.StdEncoding.EncodeToString([]byte("123")),
		},
		{
			name:  "invalid job ID format - multiple dots",
			token: base64.StdEncoding.EncodeToString([]byte("123.4.5")),
		},
		{
			name:  "invalid cluster ID",
			token: base64.StdEncoding.EncodeToString([]byte("abc.123")),
		},
		{
			name:  "invalid proc ID",
			token: base64.StdEncoding.EncodeToString([]byte("123.xyz")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DecodePageToken(tt.token)
			if err == nil {
				t.Error("DecodePageToken() expected error, got nil")
			}
		})
	}
}

// TestApplyDefaultsCarriesEveryField is the regression guard for a
// silent confinement failure: ApplyDefaults used to rebuild the struct
// from three fields, dropping FetchOpts and Owner. A caller asking for
// "my jobs only" therefore issued a query with no owner filter — the
// schedd was never asked to confine anything, and every job the caller
// could read came back.
//
// Compares against the whole struct rather than field by field, so a
// field added later without being copied fails here.
func TestApplyDefaultsCarriesEveryField(t *testing.T) {
	opts := &QueryOptions{
		Limit:      25,
		Projection: []string{"ClusterId", "Owner"},
		PageToken:  "tok",
		FetchOpts:  FetchMyJobs | FetchIncludeClusterAd,
		Owner:      "alice",
	}

	got := opts.ApplyDefaults()

	want := *opts
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ApplyDefaults() = %+v, want every field carried through: %+v", got, want)
	}
}

// TestApplyDefaultsOnlyDefaultsTheLimit checks the one field it is
// supposed to fill in, and that it does not invent a fetch option.
func TestApplyDefaultsOnlyDefaultsTheLimit(t *testing.T) {
	got := (&QueryOptions{}).ApplyDefaults()
	if got.Limit != 50 {
		t.Errorf("Limit = %d, want the default 50", got.Limit)
	}
	if got.FetchOpts != FetchNormal {
		t.Errorf("FetchOpts = %d, want FetchNormal", got.FetchOpts)
	}
	if got.Owner != "" {
		t.Errorf("Owner = %q, want empty", got.Owner)
	}

	// An explicit unlimited limit must survive.
	if unlimited := (&QueryOptions{Limit: -1}).ApplyDefaults(); unlimited.Limit != -1 {
		t.Errorf("Limit = %d, want -1 preserved", unlimited.Limit)
	}
}

// TestFetchMyJobsSurvivesIntoTheQueryAd ties the option to the wire: the
// request ad must carry the Me/MyJobs filter, since that is what a
// schedd honoring the client hint applies.
func TestFetchMyJobsSurvivesIntoTheQueryAd(t *testing.T) {
	opts := (&QueryOptions{FetchOpts: FetchMyJobs, Owner: "alice"}).ApplyDefaults()

	ad := createJobQueryAd("true", &opts)
	me, ok := ad.EvaluateAttrString("Me")
	if !ok || me != "alice" {
		t.Errorf("query ad Me = %q (present=%v), want alice", me, ok)
	}
	if _, ok := ad.Lookup("MyJobs"); !ok {
		t.Error("query ad has no MyJobs filter")
	}
}
