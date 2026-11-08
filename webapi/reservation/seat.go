package reservation

import (
	"fmt"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// SeatAd renders the spec's submit file into the job ad one seat would be.
//
// The submit file is run through the real submit machinery rather than
// parsed by hand. Submit syntax is not ad syntax, and Requirements in
// particular is composed clause by clause at submit time rather than copied
// across, so anything short of the real renderer gives a Requirements that
// matches a different set of machines than the jobs will.
//
// The project is stamped on the ad here, not left to whoever writes the
// submit file: the reservation owns which jobs may take its seats, and a
// seat whose ad does not carry the project would never match the machines
// held for it.
func (s *Spec) SeatAd() (*classad.ClassAd, error) {
	if strings.TrimSpace(s.Submit) == "" {
		return nil, fmt.Errorf("reservation %s has no submit file", s.ID)
	}
	sf, err := htcondor.ParseSubmitFile(strings.NewReader(s.Submit))
	if err != nil {
		return nil, fmt.Errorf("reservation %s: parsing the submit file: %w", s.ID, err)
	}
	// Cluster and proc zero: the ad describes the shape of a seat, not a
	// job that was ever submitted.
	ad, err := sf.MakeJobAd(htcondor.JobID{}, nil)
	if err != nil {
		return nil, fmt.Errorf("reservation %s: rendering the submit file: %w", s.ID, err)
	}
	if ad == nil {
		return nil, fmt.Errorf("reservation %s: the submit file rendered no job", s.ID)
	}
	if s.Project != "" {
		ad.InsertAttrString("ProjectName", s.Project)
	}
	return ad, nil
}

// CheckSubmit reports whether the spec's submit file renders into something
// the controller can plan against. It is meant to run when a reservation is
// created or edited, so a submit file that cannot be rendered is rejected
// while someone is looking at it rather than hours later in a drain.
func (s *Spec) CheckSubmit() error {
	ad, err := s.SeatAd()
	if err != nil {
		return err
	}
	for _, attr := range []string{"Cmd", "Requirements"} {
		if _, ok := ad.Lookup(attr); !ok {
			return fmt.Errorf("reservation %s: the rendered seat has no %s", s.ID, attr)
		}
	}
	return nil
}

// SeatResources is the shape of one seat: what a job rendered from the
// reservation's submit file asks for.
//
// A resource the submit file does not request is zero, which makes it
// unconstraining when seats are counted. Memory and disk are MB, matching
// Resources; condor_submit normalises request_memory and request_disk to
// MB and KiB respectively, so disk is scaled.
//
// When the census adapter lands this should collapse onto its SeatShape
// rather than reading the ad a second way.
func (s *Spec) SeatResources() (Resources, error) {
	ad, err := s.SeatAd()
	if err != nil {
		return Resources{}, err
	}
	num := func(attr string) float64 {
		if v, ok := ad.EvaluateAttrNumber(attr); ok && v > 0 {
			return v
		}
		return 0
	}
	return Resources{
		Cpus:     int(num("RequestCpus")),
		Gpus:     int(num("RequestGpus")),
		MemoryMB: int64(num("RequestMemory")),
		DiskMB:   int64(num("RequestDisk")) / 1024,
	}, nil
}
