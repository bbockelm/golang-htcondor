package htcondor

import (
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
