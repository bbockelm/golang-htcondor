package httpserver

import (
	"errors"
	"testing"

	"github.com/PelicanPlatform/classad/dbrpc"
)

func TestParseBucketSeconds(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false},
		{"900", 900, false},
		{"15m", 900, false},
		{"1h", 3600, false},
		{"300s", 300, false},
		{"0", 0, true},
		{"-5", 0, true},
		{"nonsense", 0, true},
	}
	for _, c := range cases {
		got, err := parseBucketSeconds(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseBucketSeconds(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("parseBucketSeconds(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseMetricsGroups(t *testing.T) {
	cols, group, err := parseMetricsGroups("RunInstanceID", "SampleTime", 900)
	if err != nil {
		t.Fatal(err)
	}
	// RunInstanceID group, then the time bucket appended last.
	if len(group) != 2 || group[0].Attr != "RunInstanceID" || group[0].BucketWidth != 0 {
		t.Errorf("group[0] = %+v, want RunInstanceID/0", group)
	}
	if group[1].Attr != "SampleTime" || group[1].BucketWidth != 900 {
		t.Errorf("group[1] = %+v, want SampleTime/900", group[1])
	}
	if cols[1].Kind != "group" || cols[1].BucketSeconds != 900 {
		t.Errorf("time column = %+v, want group/900", cols[1])
	}

	// No bucket: no time column appended.
	_, group, err = parseMetricsGroups("Owner", "SampleTime", 0)
	if err != nil || len(group) != 1 || group[0].Attr != "Owner" {
		t.Errorf("no-bucket group = %+v, err=%v", group, err)
	}

	if _, _, err := parseMetricsGroups("bad-name;drop", "SampleTime", 0); err == nil {
		t.Error("expected error on an invalid group_by attribute")
	}
}

func TestParseMetricsAggs(t *testing.T) {
	aggs, cols, err := parseMetricsAggs("max:MemoryUsage, avg:CpuUtil , count:*")
	if err != nil {
		t.Fatal(err)
	}
	if len(aggs) != 3 {
		t.Fatalf("got %d aggs, want 3", len(aggs))
	}
	if aggs[0].Func != dbrpc.AggMax || aggs[0].Arg != "MemoryUsage" {
		t.Errorf("aggs[0] = %+v", aggs[0])
	}
	if aggs[1].Func != dbrpc.AggAvg || cols[1].Name != "avg_CpuUtil" {
		t.Errorf("aggs[1]=%+v col=%+v", aggs[1], cols[1])
	}
	if aggs[2].Func != dbrpc.AggCount || aggs[2].Arg != "*" {
		t.Errorf("aggs[2] = %+v, want count:*", aggs[2])
	}

	for _, bad := range []string{"", "MemoryUsage", "bogus:X", "max:*", "max:bad-attr"} {
		if _, _, err := parseMetricsAggs(bad); err == nil {
			t.Errorf("expected error for agg %q", bad)
		}
	}
}

func TestMetricsConstraint(t *testing.T) {
	got, err := metricsConstraint("", "SampleTime", "", "")
	if err != nil || got != "true" {
		t.Errorf("empty -> %q, err=%v; want true", got, err)
	}
	got, err = metricsConstraint("ClusterId == 5", "SampleTime", "1000", "2000")
	if err != nil {
		t.Fatal(err)
	}
	want := "((ClusterId == 5) && (SampleTime >= 1000)) && (SampleTime <= 2000)"
	if got != want {
		t.Errorf("constraint = %q, want %q", got, want)
	}
	if _, err := metricsConstraint("true", "SampleTime", "notanumber", ""); err == nil {
		t.Error("expected error on non-numeric since")
	}
}

func TestMetricsUnavailable(t *testing.T) {
	if !metricsUnavailable(errors.New("dbrpc: no such archive: job_metrics")) {
		t.Error("missing archive should be unavailable")
	}
	if !metricsUnavailable(dbrpc.ErrArchiveAggregateUnsupported) {
		t.Error("unsupported should be unavailable")
	}
	if metricsUnavailable(errors.New("connection reset")) {
		t.Error("a real failure must not be treated as unavailable")
	}
}
