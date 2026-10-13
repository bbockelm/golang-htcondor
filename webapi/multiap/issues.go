package multiap

import (
	"context"
	"errors"
	"net/http"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/issues"
)

// ErrEpochsNotFederated is the answer for a read of run-attempt history
// on a hub that does not federate epoch_history.
var ErrEpochsNotFederated = &Error{Status: http.StatusNotImplemented, Reason: ReasonEpochsNotFederated,
	Msg: "the federation hub does not federate epoch_history (HTCONDORDB_FEDERATE_TABLES)"}

// ReasonEpochsNotFederated is ErrEpochsNotFederated's reason.
const ReasonEpochsNotFederated = "epoch_history_not_federated"

// IssueSource reads the issues view's records from the hub: held jobs
// from jobs, run attempts from epoch_history where the hub federates it.
// Its constraints come from issues.Collect, built on a Scope clause the
// caller passes as issues.Options.Scope; every record carries its
// ScheddName.
type IssueSource struct {
	Service *Service
}

var _ issues.Source = IssueSource{}

// JobAds implements issues.Source.
func (i IssueSource) JobAds(ctx context.Context, constraint string, projection []string, limit int) ([]*classad.ClassAd, string, error) {
	ads, err := i.Service.HubRows(ctx, TableJobs, constraint, projection, limit)
	return ads, "federation hub", err
}

// EpochAds implements issues.Source.
func (i IssueSource) EpochAds(ctx context.Context, constraint string, projection []string, limit int) ([]*classad.ClassAd, string, error) {
	if !i.Service.Hub.Federates(TableEpochHistory) {
		return nil, "", ErrEpochsNotFederated
	}
	ads, err := i.Service.HubRows(ctx, TableEpochHistory, constraint, projection, limit)
	return ads, "federation hub", err
}

// HubRows is one bounded, projected read of a hub table; ScheddName is
// always among the attributes read. A row that will not parse is an
// error.
func (s *Service) HubRows(ctx context.Context, table, constraint string, projection []string, limit int) ([]*classad.ClassAd, error) {
	var out []*classad.ClassAd
	err := s.hubStream(ctx, table, constraint, projectionWith(projection, AttrScheddName), limit, func(ad *classad.ClassAd) {
		out = append(out, ad)
	})
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return nil, err
		}
		return nil, errorf(http.StatusServiceUnavailable, "reading the federation hub's %s: %v", table, err)
	}
	return out, nil
}
