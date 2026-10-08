package httpserver

import (
	"context"
	"io/fs"

	"github.com/PelicanPlatform/classad/classad"
	htcondor "github.com/bbockelm/golang-htcondor"
)

// jupyterScheddOps is the part of the schedd the JupyterLab handlers use, so
// a unit test can stand in for it (Handler.jupyterScheddOverride).
//
// Declared apart from handlers_jupyter.go only because the submit-policy
// wiring test reads that file for SubmitRemote calls, and a method signature
// is not one. The call is in submitJupyterJob, which applies the policy.
type jupyterScheddOps interface {
	SubmitRemote(ctx context.Context, submitFile string) (int, []*classad.ClassAd, error)
	SpoolJobFilesFromFS(ctx context.Context, procAds []*classad.ClassAd, fsys fs.FS) error
	QueryWithOptions(ctx context.Context, constraint string, opts *htcondor.QueryOptions) ([]*classad.ClassAd, *htcondor.PageInfo, error)
}
