package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/bbockelm/cedar/security"
	htcondor "github.com/bbockelm/golang-htcondor"
	"github.com/bbockelm/golang-htcondor/logging"
	"github.com/bbockelm/golang-htcondor/webapi/shareurl"
	"github.com/bbockelm/golang-htcondor/webapi/spool"
)

// signShareToken and verifyShareToken wrap this server's Signer. The
// signing itself lives in webapi/shareurl because a standalone MCP
// server mints these too, with no HTTP listener of its own.
func (s *Handler) signShareToken(p shareurl.Payload) (string, error) {
	if s.shareSigner == nil {
		return "", fmt.Errorf("share URL signing is not configured")
	}
	return s.shareSigner.Sign(p)
}

func (s *Handler) verifyShareToken(tok string, want shareurl.Kind) (*shareurl.Payload, error) {
	if s.shareSigner == nil {
		return nil, fmt.Errorf("share URL signing is not configured")
	}
	return s.shareSigner.Verify(tok, want)
}

// shareURLBase returns the absolute URL prefix to use when minting share
// URLs. Falls back to deriving from the request when HTTPBaseURL is not
// configured — works for typical deployments behind a single proxy/host.
func (s *Handler) shareURLBase(r *http.Request) string {
	// An operator-set HTTP_API_BASE_URL is authoritative: it is the
	// canonical public URL, and it should win even when a caller reaches
	// the server by some other name.
	//
	// It is empty unless set: publicBaseURL deliberately does not fall
	// back to FULL_HOSTNAME, which inside a container is the pod name.
	// Guessing produced share links nobody could open. With no
	// configured value the request's own Host is used below, which is
	// right by construction -- the caller reached us at it.
	if s.httpBaseURL != "" {
		return strings.TrimRight(s.httpBaseURL, "/")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	host := r.Host
	if fwd := r.Header.Get("X-Forwarded-Host"); fwd != "" {
		host = fwd
	}
	if host == "" {
		// No Host at all (HTTP/1.0, or a synthetic request). Fall back to
		// the derived value: wrong outside the cluster, but better than
		// emitting a URL with an empty authority.
		return strings.TrimRight(s.httpBaseURL, "/")
	}
	return fmt.Sprintf("%s://%s", scheme, host)
}

// ShareOutputRequest is the body for POST /api/v1/jobs/{id}/output/share.
type ShareOutputRequest struct {
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// ShareOutputResponse is what the SPA gets back. Owner is echoed for UX
// so the share preview can label the URL with "downloads as <owner>".
type ShareOutputResponse struct {
	URL        string    `json:"url"`
	ExpiresAt  time.Time `json:"expires_at"`
	TTLSeconds int       `json:"ttl_seconds"`
	Owner      string    `json:"owner"`
}

// handleJobOutputShare handles POST /api/v1/jobs/{id}/output/share.
// Mints a short-lived URL that anyone can use to download the job's
// sandbox without authenticating. The URL is bound to one specific job
// and to the requesting user (the URL impersonates them at redeem time).
func (s *Handler) handleJobOutputShare(w http.ResponseWriter, r *http.Request, jobID string) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Public shares need to act on behalf of the job owner at redeem time;
	// that requires a signing key for JWT minting. Bail early with a
	// helpful message rather than producing an unusable URL.
	if s.signingKeyPath == "" {
		s.writeError(w, http.StatusNotImplemented,
			"Share URLs require HTTP_API_SIGNING_KEY (or SEC_TOKEN_POOL_SIGNING_KEY_FILE) to be configured")
		return
	}

	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	cluster, proc, err := parseJobID(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}

	ttl := shareurl.ClampTTL(shareurl.KindOutput, requestedTTL(r))

	// Owner = authenticated user without "@uidDomain" — schedd's Owner
	// attribute uses the bare username; we re-add the suffix at redeem
	// time when minting the JWT.
	owner := strings.SplitN(htcondor.GetAuthenticatedUserFromContext(ctx), "@", 2)[0]
	if owner == "" {
		s.writeError(w, http.StatusUnauthorized, "Could not determine authenticated user")
		return
	}

	// Verify the requester actually owns the job before signing a
	// share URL. Without this check, a user could mint a share URL
	// for another user's job — the redeemer JWT would be issued as
	// the requester, so a strict schedd ACL would refuse the
	// download, but on a permissively-configured READ ACL it could
	// succeed (and the audit log would show the requester as the
	// downloader, hiding the actual data subject).
	jobConstraint := fmt.Sprintf("ClusterId == %d && ProcId == %d && Owner == %s",
		cluster, proc, classadStringLit(owner))
	// getSchedd, not the s.schedd snapshot: this server replaces its
	// schedd handle when the collector reports a new address, and a
	// captured pointer keeps dialling a socket that no longer exists.
	ads, _, qerr := s.getSchedd().QueryWithOptions(ctx, jobConstraint, &htcondor.QueryOptions{
		Projection: []string{"ClusterId", "ProcId", "Owner"},
		Limit:      1,
	})
	if qerr != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("ownership check failed: %v", qerr))
		return
	}
	if len(ads) == 0 {
		// Either the job doesn't exist or it's owned by someone
		// else. Return 404 in both cases — we don't want to
		// disclose the existence of jobs the user doesn't own.
		s.writeError(w, http.StatusNotFound, "Job not found")
		return
	}

	exp := time.Now().Add(ttl)
	tok, err := s.signShareToken(shareurl.Payload{
		Cluster: cluster,
		Proc:    proc,
		Owner:   owner,
		Exp:     exp.Unix(),
		Kind:    shareurl.KindOutput,
	})
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to sign token: %v", err))
		return
	}

	url := fmt.Sprintf("%s/api/v1/share/output?t=%s", s.shareURLBase(r), tok)
	s.writeJSON(w, http.StatusOK, ShareOutputResponse{
		URL:        url,
		ExpiresAt:  exp,
		TTLSeconds: int(ttl.Seconds()),
		Owner:      owner,
	})
}

// handleSharedOutput handles GET /api/v1/share/output?t=<token>.
// Verifies the token, mints a fresh server-signed JWT for the embedded
// owner, and streams the job's sandbox as a tar. Possession of the URL
// is the only auth — the SPA's session cookie is intentionally ignored.
func (s *Handler) handleSharedOutput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.signingKeyPath == "" {
		s.writeError(w, http.StatusNotImplemented, "Share URLs are not configured")
		return
	}

	tok := r.URL.Query().Get("t")
	if tok == "" {
		s.writeError(w, http.StatusBadRequest, "Missing token")
		return
	}
	payload, err := s.verifyShareToken(tok, shareurl.KindOutput)
	if err != nil {
		// Don't leak which check failed (signature vs expiry).
		s.logger.Info(logging.DestinationHTTP, "Share token rejected", "error", err)
		s.writeError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	ctx, err := s.redeemContext(r, payload.Owner)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to build redeem context", "error", err)
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jobID := fmt.Sprintf("%d.%d", payload.Cluster, payload.Proc)
	constraint := fmt.Sprintf("ClusterId == %d && ProcId == %d", payload.Cluster, payload.Proc)

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"job-%s-output.tar\"", jobID))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)

	errChan := s.getSchedd().ReceiveJobSandbox(ctx, constraint, w)
	if err := <-errChan; err != nil {
		// Headers and body already started; just log.
		s.logger.Error(logging.DestinationSchedd,
			"Error streaming shared sandbox", "job_id", jobID, "error", err)
	}
}

// requestedTTL reads an optional {"ttl_seconds": N} body. A body that is
// absent, empty, or unparseable means "use the default" -- the caller
// asked for a share URL, and refusing over a malformed optional knob
// would be a worse answer than the default lifetime.
func requestedTTL(r *http.Request) time.Duration {
	if r.Body == nil || r.ContentLength == 0 {
		return 0
	}
	var req ShareOutputRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.TTLSeconds <= 0 {
		return 0
	}
	return time.Duration(req.TTLSeconds) * time.Second
}

// redeemContext builds the schedd-facing context a redeemed share token
// acts under: a freshly minted, short-lived JWT for the token's owner,
// cached and wrapped in a TOKEN-only SecurityConfig.
//
// WithToken alone is not enough -- every schedd path reads the
// SecurityConfig directly from ctx (see schedd_transfer.go,
// NewQmgmtConnection). This mirrors the tail of
// createAuthenticatedContext.
//
// The returned errors are safe to show a caller: they name missing
// server configuration, not anything about the token.
func (s *Handler) redeemContext(r *http.Request, owner string) (context.Context, error) {
	// Re-add the @uidDomain suffix the schedd's Owner attribute lacks.
	username := owner
	if !strings.Contains(username, "@") {
		if s.uidDomain == "" {
			return nil, fmt.Errorf("UID_DOMAIN not configured; cannot redeem share token")
		}
		username = username + "@" + s.uidDomain
	}
	if s.trustDomain == "" {
		return nil, fmt.Errorf("TRUST_DOMAIN not configured; cannot redeem share token")
	}

	now := time.Now()
	jwt, err := security.GenerateJWT(
		filepath.Dir(s.signingKeyPath),
		filepath.Base(s.signingKeyPath),
		username,
		s.trustDomain,
		now.Unix(),
		now.Add(2*time.Minute).Unix(),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to authorize share token")
	}
	entry, err := s.tokenCache.AddValidated(jwt, username, now.Add(2*time.Minute))
	if err != nil {
		return nil, fmt.Errorf("failed to authorize share token")
	}
	secConfig, err := ConfigureSecurityForTokenWithCacheAndFallback(jwt, entry.SessionCache, false)
	if err != nil {
		return nil, fmt.Errorf("failed to authorize share token")
	}
	ctx := WithToken(r.Context(), jwt)
	ctx = htcondor.WithSecurityConfig(ctx, secConfig)
	ctx = htcondor.WithAuthenticatedUser(ctx, username)
	return ctx, nil
}

// ShareInputUpload is one job's upload URL.
//
// ExpectedFiles is the load-bearing field: the schedd accepts only the
// names in a job's allow-set and drops the rest of the tar in silence,
// and whoever redeems this URL is often not the person who wrote the
// submit file. Without the list they have no way to learn which names
// are expected until the job fails at execute time on a missing file.
// It is per-proc because the allow-set is: procs of one cluster can
// list different inputs.
type ShareInputUpload struct {
	JobID         string   `json:"job_id"`
	URL           string   `json:"url"`
	ExpectedFiles []string `json:"expected_files"`
}

// ShareInputResponse is what a mint call returns. Always a list, even
// for a single proc: HTCondor spools per proc, so "the upload URL for
// this submission" is inherently plural, and one shape is easier to
// consume than a response that changes with the request.
//
// Owner and the expiry are shared by every URL in one response; only
// the URL and its allow-set vary per proc.
type ShareInputResponse struct {
	ClusterID      int                `json:"cluster_id"`
	Owner          string             `json:"owner"`
	ExpiresAt      time.Time          `json:"expires_at"`
	TTLSeconds     int                `json:"ttl_seconds"`
	Count          int                `json:"count"`
	ProcsRemaining int                `json:"procs_remaining,omitempty"`
	Uploads        []ShareInputUpload `json:"uploads"`
	Note           string             `json:"note,omitempty"`
}

// handleJobInputShare handles POST /api/v1/jobs/{id}/input/share.
// Mints short-lived URLs that anyone can PUT a tar of input files to,
// without authenticating. Each URL is bound to one proc and to the
// requesting user, whom it impersonates at redeem time.
//
// A bare cluster id mints one URL for every proc of the cluster still
// awaiting input; "cluster.proc" mints exactly one. HTCondor spools per
// proc, so a `queue N` submission genuinely needs N uploads -- the
// sibling upload endpoints fan out the same way.
func (s *Handler) handleJobInputShare(w http.ResponseWriter, r *http.Request, jobID string) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.signingKeyPath == "" {
		s.writeError(w, http.StatusNotImplemented,
			"Share URLs require HTTP_API_SIGNING_KEY (or SEC_TOKEN_POOL_SIGNING_KEY_FILE) to be configured")
		return
	}

	ctx, needsRedirect, err := s.requireAuthentication(r)
	if err != nil {
		if needsRedirect {
			s.redirectToLogin(w, r)
			return
		}
		s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
		return
	}

	target, err := spool.ParseTarget(jobID)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid job ID: %v", err))
		return
	}
	ttl := shareurl.ClampTTL(shareurl.KindInput, requestedTTL(r))

	// Owner without "@uidDomain" -- the schedd's Owner attribute uses
	// the bare username; redeemContext re-adds the suffix.
	owner := strings.SplitN(htcondor.GetAuthenticatedUserFromContext(ctx), "@", 2)[0]
	if owner == "" {
		s.writeError(w, http.StatusUnauthorized, "Could not determine authenticated user")
		return
	}
	// Ownership is checked here for the same reason the download share
	// checks it: the redeem JWT is issued as the requester, so without
	// this a permissive schedd READ ACL would let someone mint a URL
	// that writes into a job they do not own.
	ownerScope := func(c string) (string, error) {
		return fmt.Sprintf("(%s) && Owner == %s", c, classadStringLit(owner)), nil
	}

	procAds, remaining, err := s.procAdsToMintFor(ctx, target, ownerScope)
	if err != nil {
		s.writeSpoolError(w, err)
		return
	}
	if len(procAds) == 0 {
		// Nothing to mint for, and the two reasons need different
		// answers: a job that is not there at all versus a job that is
		// there and past the point of accepting input.
		if target.AllProcs {
			s.writeError(w, http.StatusNotFound, fmt.Sprintf(
				"No proc of cluster %d is awaiting input. Either the cluster does not exist, "+
					"it belongs to another user, or its input has already been spooled.", target.Cluster))
			return
		}
		s.writeError(w, http.StatusNotFound, fmt.Sprintf(
			"Job %s is not awaiting input. Either it does not exist, it belongs to another user, "+
				"or its input has already been spooled -- only a job held for input spooling "+
				"accepts an upload.", jobID))
		return
	}

	exp := time.Now().Add(ttl)
	uploads := make([]ShareInputUpload, 0, len(procAds))
	for _, ad := range procAds {
		cluster, proc, ok := procIDOf(ad)
		if !ok {
			continue
		}
		tok, terr := s.signShareToken(shareurl.Payload{
			Cluster: cluster,
			Proc:    proc,
			Owner:   owner,
			Exp:     exp.Unix(),
			Kind:    shareurl.KindInput,
		})
		if terr != nil {
			s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to sign token: %v", terr))
			return
		}
		uploads = append(uploads, ShareInputUpload{
			JobID:         fmt.Sprintf("%d.%d", cluster, proc),
			URL:           fmt.Sprintf("%s/api/v1/share/input?t=%s", s.shareURLBase(r), tok),
			ExpectedFiles: htcondor.SpoolInputAllowSet(ad),
		})
	}

	resp := ShareInputResponse{
		ClusterID:      target.Cluster,
		Owner:          owner,
		ExpiresAt:      exp,
		TTLSeconds:     int(ttl.Seconds()),
		Count:          len(uploads),
		ProcsRemaining: remaining,
		Uploads:        uploads,
	}
	// Never let a cap read as "this is the whole cluster".
	if remaining > 0 {
		resp.Note = fmt.Sprintf(
			"%d more proc(s) of this cluster are awaiting input; one call mints at most %d. "+
				"Call again for the rest.", remaining, maxMintedURLs)
	}
	s.writeJSON(w, http.StatusOK, resp)
}

// maxMintedURLs bounds one mint call. It is the same ceiling the spool
// fan-out uses, for the same reason: past it the answer is not a longer
// list of URLs but HTTP/HTTPS URLs in transfer_input_files, which the
// execute nodes fetch themselves.
var maxMintedURLs = spool.DefaultLimits().MaxProcs

// procAdsToMintFor resolves a target to the proc ads a mint should cover:
// one for "cluster.proc", every proc still awaiting input for a bare
// cluster id. The second return is how many more procs were awaiting
// input than this call will mint for.
func (s *Handler) procAdsToMintFor(
	ctx context.Context,
	target spool.Target,
	ownerScope func(string) (string, error),
) ([]*classad.ClassAd, int, error) {
	if !target.AllProcs {
		ad, err := fetchProcAdForSpoolWith(ctx, s.getSchedd(), target.Cluster, target.Proc,
			ownerScope, jobInputShareProjection)
		if err != nil || ad == nil {
			return nil, 0, err
		}
		if !awaitingInputSpool(ad) {
			return nil, 0, nil
		}
		return []*classad.ClassAd{ad}, 0, nil
	}

	ads, err := spool.FetchProcAdsAwaitingInput(ctx, s.getSchedd(), target.Cluster,
		maxMintedURLs, ownerScope, jobInputShareProjection)
	if err != nil {
		return nil, 0, err
	}
	if len(ads) > maxMintedURLs {
		return ads[:maxMintedURLs], len(ads) - maxMintedURLs, nil
	}
	return ads, 0, nil
}

// procIDOf reads a proc ad's cluster and proc. See spool.ProcIDOf.
func procIDOf(ad *classad.ClassAd) (int, int, bool) { return spool.ProcIDOf(ad) }

// SharedInputResult is what a redeemed upload returns. Unexpected names
// the schedd dropped are reported rather than swallowed -- see
// ShareInputResponse.ExpectedFiles.
type SharedInputResult struct {
	Message       string   `json:"message"`
	JobID         string   `json:"job_id"`
	ExpectedFiles []string `json:"expected_files"`
	IgnoredFiles  []string `json:"ignored_files,omitempty"`
	Warning       string   `json:"warning,omitempty"`
}

// handleSharedInput handles PUT /api/v1/share/input?t=<token>.
// Verifies the token and streams the request body -- a tar of the job's
// input files -- into its spool. Possession of the URL is the only auth;
// any session cookie on the request is intentionally ignored.
func (s *Handler) handleSharedInput(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if s.signingKeyPath == "" {
		s.writeError(w, http.StatusNotImplemented, "Share URLs are not configured")
		return
	}

	tok := r.URL.Query().Get("t")
	if tok == "" {
		s.writeError(w, http.StatusBadRequest, "Missing token")
		return
	}
	payload, err := s.verifyShareToken(tok, shareurl.KindInput)
	if err != nil {
		// Don't leak which check failed (signature vs expiry vs kind).
		s.logger.Info(logging.DestinationHTTP, "Share upload token rejected", "error", err)
		s.writeError(w, http.StatusUnauthorized, "Invalid or expired token")
		return
	}

	ctx, err := s.redeemContext(r, payload.Owner)
	if err != nil {
		s.logger.Error(logging.DestinationHTTP, "Failed to build redeem context", "error", err)
		s.writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jobID := payload.JobID()
	// Scope the lookup to the token's owner even though the mint checked
	// ownership. A schedd whose queue has been reset hands out cluster
	// ids again from the start, so an outstanding token for 42.0 can
	// outlive the job it was minted for and name somebody else's new one.
	// Scoped, that token finds nothing instead of writing into it.
	procAd, err := fetchProcAdForSpoolWith(ctx, s.getSchedd(), payload.Cluster, payload.Proc,
		func(c string) (string, error) {
			return fmt.Sprintf("(%s) && Owner == %s", c, classadStringLit(payload.Owner)), nil
		}, jobInputShareProjection)
	if err != nil {
		s.writeSpoolError(w, err)
		return
	}
	if procAd == nil {
		s.writeError(w, http.StatusNotFound, fmt.Sprintf("Job %s not found", jobID))
		return
	}
	// The job's state, not the token's expiry, is what really bounds an
	// upload URL: once the spool completes the job leaves this state and
	// the URL is inert. Say so plainly instead of letting a second upload
	// fail somewhere deeper with a less recoverable message.
	if !awaitingInputSpool(procAd) {
		s.writeError(w, http.StatusConflict, fmt.Sprintf(
			"Job %s is no longer awaiting input -- its input may already have been uploaded.", jobID))
		return
	}
	expected := htcondor.SpoolInputAllowSet(procAd)

	// MaxBytesReader, not io.LimitReader: a LimitReader reports its cap
	// as io.EOF, indistinguishable from the end of the upload, so an
	// oversized body would spool as a silently truncated tar.
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	names := newTarNameRecorder()
	body := io.TeeReader(r.Body, names)

	if err := s.getSchedd().SpoolJobFilesFromTar(ctx, []*classad.ClassAd{procAd}, body); err != nil {
		if isAuthenticationError(err) {
			s.writeError(w, http.StatusUnauthorized, fmt.Sprintf("Authentication failed: %v", err))
			return
		}
		s.writeError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to spool job files: %v", err))
		return
	}

	result := SharedInputResult{
		Message:       "Job input files uploaded successfully",
		JobID:         jobID,
		ExpectedFiles: expected,
	}
	if ignored := names.Unexpected(expected); len(ignored) > 0 {
		result.IgnoredFiles = ignored
		result.Warning = fmt.Sprintf(
			"%d uploaded file(s) are not in this job's input list and were dropped by the schedd; "+
				"the job will run without them.", len(ignored))
		s.logger.Info(logging.DestinationHTTP, "Share upload carried files outside the allow-set",
			"job_id", jobID, "ignored", ignored, "expected", expected)
	}
	s.writeJSON(w, http.StatusOK, result)
}
