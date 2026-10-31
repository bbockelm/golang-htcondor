package htcondor

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// setGSICredentials stores the two credential settings
// SubmitHash::SetGSICredentials writes from the submit file:
// DelegateJobGSICredentialsLifetime and ScitokensFile.
//
// The X.509 proxy half of that setter is deliberately not here. It reads the
// proxy FILE to copy its subject, VOMS attributes and expiration into the job
// ad, which is host access this parser does not do, and it is dead weight for
// a pool that authenticates with tokens.
func (sf *SubmitFile) setGSICredentials(ad *classad.ClassAd) error {
	if err := sf.setDelegateLifetime(ad); err != nil {
		return err
	}
	return sf.setScitokensFile(ad)
}

// setDelegateLifetime stores delegate_job_GSI_credentials_lifetime, the
// number of seconds of the submitter's credential the schedd delegates with
// the job.
//
// condor_submit reads the value with strtol and requires the WHOLE string to
// be an integer -- it is not an expression and not a time with a unit -- and
// aborts the submission over anything else, which is what the error here is.
func (sf *SubmitFile) setDelegateLifetime(ad *classad.ClassAd) error {
	value, ok := sf.simpleKeywordParam("delegate_job_gsi_credentials_lifetime", "DelegateJobGSICredentialsLifetime")
	if !ok {
		return nil
	}
	lifetime, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid integer setting delegate_job_GSI_credentials_lifetime = %s", value)
	}
	_ = ad.Set("DelegateJobGSICredentialsLifetime", lifetime)
	return nil
}

// setScitokensFile stores the path to the SciToken the job is submitted with,
// which is what the schedd reads to refresh the job's credential.
//
// The decision is `use_scitokens` (`use_scitoken` is the alternate spelling)
// crossed with whether a file was named:
//
//   - neither said: nothing is written.
//   - a file named, nothing else said: write it.
//   - use_scitokens = true: write the named file, or BEARER_TOKEN_FILE from
//     the environment; with neither, condor_submit aborts and so does this.
//   - use_scitokens = auto: write the named file if there is one, else the
//     environment's file if it has one, else nothing -- "auto" never fails.
//   - use_scitokens = false: write nothing, even with a file named.
//
// The path is stored as a full path against Iwd, the same as every other
// submit-side file.
func (sf *SubmitFile) setScitokensFile(ad *classad.ClassAd) error {
	useCmd, hasUseCmd := sf.simpleKeywordParam("use_scitokens", "use_scitoken")
	file, _ := sf.simpleKeywordParam("scitokens_file", "ScitokensFile")

	use := file != ""
	if hasUseCmd {
		switch {
		case strings.EqualFold(strings.TrimSpace(useCmd), "auto"):
			use = file != "" || sf.bearerTokenFile() != ""
		default:
			b, ok := evalBoolParam(useCmd)
			if !ok {
				return fmt.Errorf("use_scitokens error. Value should be true, false, or auto")
			}
			use = b
		}
	}
	if !use {
		return nil
	}

	tokenFile := file
	if tokenFile == "" {
		tokenFile = sf.bearerTokenFile()
	}
	if tokenFile == "" {
		return fmt.Errorf("no SciTokens filename specified: expected either the scitokens_file " +
			"command or the BEARER_TOKEN_FILE environment variable to be set")
	}
	iwd, err := sf.jobIwd()
	if err != nil {
		return err
	}
	_ = ad.Set("ScitokensFile", fullPath(tokenFile, iwd))
	return nil
}

// bearerTokenFile is the BEARER_TOKEN_FILE environment variable, which
// condor_submit falls back to when the submit file names no SciToken.
//
// It is the submitting PROCESS's environment, so it is answered only when the
// parse is allowed to reach the host it runs on. A daemon parsing a submit
// file it received over the network would otherwise hand the job its own
// token path; see SubmitParseOptions.AllowLocalAccess.
func (sf *SubmitFile) bearerTokenFile() string {
	if sf == nil || !sf.localAccess {
		return ""
	}
	return os.Getenv("BEARER_TOKEN_FILE")
}
