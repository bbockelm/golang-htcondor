package reservation

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/PelicanPlatform/classad/classad"

	htcondor "github.com/bbockelm/golang-htcondor"
)

// ads parses old-format ClassAd text into the slice MachinesFromAds takes.
func ads(t *testing.T, texts ...string) []*classad.ClassAd {
	t.Helper()
	out := make([]*classad.ClassAd, 0, len(texts))
	for _, text := range texts {
		ad, err := classad.ParseOld(text)
		if err != nil {
			t.Fatalf("parsing %q: %v", text, err)
		}
		out = append(out, ad)
	}
	return out
}

const (
	jobStartA = 1_700_000_000
	jobStartB = 1_700_003_600
)

func TestMachinesFromAds(t *testing.T) {
	tests := []struct {
		name string
		ads  []string
		want []Machine
	}{
		{
			// The ordinary case: a partitionable slot with what it has
			// left to carve, plus the two jobs it has already carved.
			name: "pslot with dslots",
			ads: []string{
				`Name = "slot1@wn01"
Machine = "wn01"
SlotType = "Partitionable"
PartitionableSlot = true
State = "Unclaimed"
Cpus = 6
GPUs = 1
Memory = 24576
Disk = 6291456`,
				`Name = "slot1_1@wn01"
Machine = "wn01"
SlotType = "Dynamic"
DynamicSlot = true
State = "Claimed"
Activity = "Busy"
Cpus = 1
GPUs = 0
Memory = 4096
Disk = 1048576
JobStart = 1700000000`,
				`Name = "slot1_2@wn01"
Machine = "wn01"
SlotType = "Dynamic"
DynamicSlot = true
State = "Claimed"
Activity = "Busy"
Cpus = 1
GPUs = 1
Memory = 4096
Disk = 1048576
JobStart = 1700003600`,
			},
			want: []Machine{{
				Name: "wn01",
				Free: Resources{Cpus: 6, Gpus: 1, MemoryMB: 24576, DiskMB: 6144},
				Dslots: []Dslot{
					{Started: time.Unix(jobStartA, 0), Res: Resources{Cpus: 1, MemoryMB: 4096, DiskMB: 1024}},
					{Started: time.Unix(jobStartB, 0), Res: Resources{Cpus: 1, Gpus: 1, MemoryMB: 4096, DiskMB: 1024}},
				},
			}},
		},
		{
			// Nothing running: the whole machine is Free and there is
			// nothing to evict.
			name: "idle machine",
			ads: []string{
				`Name = "slot1@wn02"
Machine = "wn02"
PartitionableSlot = true
State = "Unclaimed"
Cpus = 8
GPUs = 2
Memory = 32768
Disk = 8388608`,
			},
			want: []Machine{{
				Name: "wn02",
				Free: Resources{Cpus: 8, Gpus: 2, MemoryMB: 32768, DiskMB: 8192},
			}},
		},
		{
			// A job already serving another reservation. Project has to
			// survive the trip, because SeatsOn refuses to evict a slot
			// that carries one.
			name: "slot held by another project",
			ads: []string{
				`Name = "slot1@wn03"
Machine = "wn03"
PartitionableSlot = true
Cpus = 2
Memory = 8192
Disk = 2097152`,
				`Name = "slot1_1@wn03"
Machine = "wn03"
DynamicSlot = true
State = "Claimed"
Cpus = 2
Memory = 8192
Disk = 2097152
JobStart = 1700000000
RemoteProject = "Atlas"`,
			},
			want: []Machine{{
				Name: "wn03",
				Free: Resources{Cpus: 2, MemoryMB: 8192, DiskMB: 2048},
				Dslots: []Dslot{{
					Started: time.Unix(jobStartA, 0),
					Res:     Resources{Cpus: 2, MemoryMB: 8192, DiskMB: 2048},
					Project: "Atlas",
				}},
			}},
		},
		{
			// A static pool: an unclaimed slot is capacity, a claimed
			// one is a job. Neither says PartitionableSlot.
			name: "static slots",
			ads: []string{
				`Name = "slot1@wn04"
Machine = "wn04"
SlotType = "Static"
State = "Unclaimed"
Cpus = 4
Memory = 8192
Disk = 1048576`,
				`Name = "slot2@wn04"
Machine = "wn04"
SlotType = "Static"
State = "Claimed"
Activity = "Busy"
Cpus = 4
Memory = 8192
Disk = 1048576
JobStart = 1700000000`,
			},
			want: []Machine{{
				Name: "wn04",
				Free: Resources{Cpus: 4, MemoryMB: 8192, DiskMB: 1024},
				Dslots: []Dslot{{
					Started: time.Unix(jobStartA, 0),
					Res:     Resources{Cpus: 4, MemoryMB: 8192, DiskMB: 1024},
				}},
			}},
		},
		{
			// A claimed slot between jobs. It has no JobStart, which is
			// the idle case census.go already models -- and precisely
			// the reading that must not leak onto a running job.
			name: "claimed but idle",
			ads: []string{
				`Name = "slot1_1@wn05"
Machine = "wn05"
DynamicSlot = true
State = "Claimed"
Activity = "Idle"
Cpus = 1
Memory = 2048
Disk = 1048576`,
			},
			want: []Machine{{
				Name:   "wn05",
				Dslots: []Dslot{{Res: Resources{Cpus: 1, MemoryMB: 2048, DiskMB: 1024}}},
			}},
		},
		{
			// No Machine attribute, a string where a number belongs, an
			// undefined reference, a negative leftover, and a JobStart
			// of zero. None of it should produce a machine that claims
			// capacity it does not have.
			name: "missing and odd attributes",
			ads: []string{
				`Name = "slot1@wn06.example.net"
PartitionableSlot = true
Cpus = "lots"
Memory = NoSuchAttribute
Disk = -4096
JobStart = 0`,
			},
			want: []Machine{{Name: "wn06.example.net"}},
		},
		{
			// A machine named only by its slot, with no "@" to split on.
			name: "slot name without a host",
			ads: []string{
				`Name = "standalone"
PartitionableSlot = true
Cpus = 2
Memory = 4096
Disk = 1048576`,
			},
			want: []Machine{{
				Name: "standalone",
				Free: Resources{Cpus: 2, MemoryMB: 4096, DiskMB: 1024},
			}},
		},
		{
			// Two machines interleaved, to pin that grouping is by
			// Machine and that the order of first appearance holds.
			name: "two machines interleaved",
			ads: []string{
				`Name = "slot1@wn07"
Machine = "wn07"
PartitionableSlot = true
Cpus = 1
Memory = 1024
Disk = 1048576`,
				`Name = "slot1@wn08"
Machine = "wn08"
PartitionableSlot = true
Cpus = 2
Memory = 2048
Disk = 1048576`,
				`Name = "slot1_1@wn07"
Machine = "wn07"
DynamicSlot = true
State = "Claimed"
Cpus = 3
Memory = 3072
Disk = 1048576
JobStart = 1700000000`,
			},
			want: []Machine{
				{
					Name: "wn07",
					Free: Resources{Cpus: 1, MemoryMB: 1024, DiskMB: 1024},
					Dslots: []Dslot{{
						Started: time.Unix(jobStartA, 0),
						Res:     Resources{Cpus: 3, MemoryMB: 3072, DiskMB: 1024},
					}},
				},
				{
					Name: "wn08",
					Free: Resources{Cpus: 2, MemoryMB: 2048, DiskMB: 1024},
				},
			},
		},
		{
			name: "no ads",
			ads:  nil,
			want: []Machine{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MachinesFromAds(ads(t, tt.ads...))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MachinesFromAds() =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

// TestMachinesFromAdsSkipsNil guards the one input the collector can hand
// back that has no slot in it at all.
func TestMachinesFromAdsSkipsNil(t *testing.T) {
	got := MachinesFromAds([]*classad.ClassAd{nil})
	if len(got) != 0 {
		t.Errorf("a nil ad produced %d machines, want 0", len(got))
	}
}

// TestRemainingIsLeftUnset pins the contract this branch documents: the
// estimator's bound is somebody else's job to fill in.
func TestRemainingIsLeftUnset(t *testing.T) {
	got := MachinesFromAds(ads(t, `Name = "slot1_1@wn09"
Machine = "wn09"
DynamicSlot = true
State = "Claimed"
Cpus = 1
JobStart = 1700000000`))
	if len(got) != 1 || len(got[0].Dslots) != 1 {
		t.Fatalf("expected one machine with one d-slot, got %+v", got)
	}
	if got[0].Dslots[0].Remaining != 0 {
		t.Errorf("Remaining = %v, want 0", got[0].Dslots[0].Remaining)
	}
}

func TestSeatShapeFromJobAd(t *testing.T) {
	tests := []struct {
		name string
		ad   string
		want Resources
	}{
		{
			name: "all four requested",
			ad: `RequestCpus = 4
RequestGpus = 2
RequestMemory = 8192
RequestDisk = 10485760`,
			want: Resources{Cpus: 4, Gpus: 2, MemoryMB: 8192, DiskMB: 10240},
		},
		{
			name: "nothing requested takes the defaults",
			ad:   `Owner = "alice"`,
			want: Resources{Cpus: 1, MemoryMB: 1024, DiskMB: 1024},
		},
		{
			// The reason these are evaluated and not read as literals: a
			// submit file is free to write arithmetic, and a literal read
			// would quietly fall back to the default.
			name: "expressions are evaluated",
			ad: `RequestCpus = 2 * 2
RequestMemory = 2 * 1024
RequestDisk = 1024 * 1024`,
			want: Resources{Cpus: 4, MemoryMB: 2048, DiskMB: 1024},
		},
		{
			name: "an expression over another attribute",
			ad: `Threads = 8
RequestCpus = Threads / 2`,
			want: Resources{Cpus: 4, MemoryMB: 1024, DiskMB: 1024},
		},
		{
			name: "fractional asks round up to a whole unit",
			ad: `RequestCpus = 1.5
RequestMemory = 1024.5
RequestDisk = 1536`,
			want: Resources{Cpus: 2, MemoryMB: 1025, DiskMB: 2},
		},
		{
			name: "undefined and non-numeric take the defaults",
			ad: `RequestCpus = NoSuchAttribute
RequestMemory = "a lot"
RequestGpus = undefined`,
			want: Resources{Cpus: 1, MemoryMB: 1024, DiskMB: 1024},
		},
		{
			name: "zero and negative take the defaults",
			ad: `RequestCpus = 0
RequestGpus = -1
RequestMemory = -2048`,
			want: Resources{Cpus: 1, MemoryMB: 1024, DiskMB: 1024},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SeatShapeFromJobAd(ads(t, tt.ad)[0])
			if got != tt.want {
				t.Errorf("SeatShapeFromJobAd() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSeatShapeFromNilAd(t *testing.T) {
	want := Resources{Cpus: 1, MemoryMB: 1024, DiskMB: 1024}
	if got := SeatShapeFromJobAd(nil); got != want {
		t.Errorf("SeatShapeFromJobAd(nil) = %+v, want %+v", got, want)
	}
}

// fakeQuerier records what Census asked for and replays a canned answer.
type fakeQuerier struct {
	adType     string
	constraint string
	opts       *htcondor.QueryOptions
	ads        []*classad.ClassAd
	err        error
}

func (f *fakeQuerier) QueryAdsWithOptions(_ context.Context, adType, constraint string, opts *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error) {
	f.adType, f.constraint, f.opts = adType, constraint, opts
	return f.ads, nil, f.err
}

// TestCensusSendsAProjection is the guard on the trap in this adapter: a
// collector query with no projection comes back with a handful of
// attributes, and an absent JobStart would read as a brand-new job on
// every slot in the pool.
func TestCensusSendsAProjection(t *testing.T) {
	q := &fakeQuerier{ads: ads(t, `Name = "slot1@wn10"
Machine = "wn10"
PartitionableSlot = true
Cpus = 4
Memory = 8192
Disk = 1048576`)}

	got, err := Census(context.Background(), q)
	if err != nil {
		t.Fatalf("Census: %v", err)
	}
	if q.adType != "StartdAd" {
		t.Errorf("queried %q, want StartdAd", q.adType)
	}
	if q.constraint != SlotConstraint {
		t.Errorf("constraint %q, want %q", q.constraint, SlotConstraint)
	}
	if q.opts == nil {
		t.Fatal("Census sent no query options, so the collector would truncate the projection")
	}
	if q.opts.Limit <= 0 {
		t.Errorf("Limit = %d; the collector defaults to 50 ads when it is unset", q.opts.Limit)
	}
	for _, want := range []string{"JobStart", "RemoteProject", "Cpus", "GPUs", "Memory", "Disk", "Machine"} {
		found := false
		for _, a := range q.opts.Projection {
			if a == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("projection is missing %q: %v", want, q.opts.Projection)
		}
	}
	if len(got) != 1 || got[0].Name != "wn10" {
		t.Errorf("Census() = %+v, want one machine wn10", got)
	}
}

func TestCensusPropagatesError(t *testing.T) {
	boom := errors.New("collector unreachable")
	if _, err := Census(context.Background(), &fakeQuerier{err: boom}); !errors.Is(err, boom) {
		t.Errorf("Census error = %v, want %v", err, boom)
	}
}
