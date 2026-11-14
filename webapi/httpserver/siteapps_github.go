// Copyright 2026 Morgridge Institute for Research
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/siteapps"
)

// Installing a site app from a GitHub release.
//
// WHY THE SERVER FETCHES AND NOT THE BROWSER. The admin page can read a
// repository's releases by itself: api.github.com answers with
// `Access-Control-Allow-Origin: *`. It cannot read the bundle. A
// release asset redirects to release-assets.githubusercontent.com, and
// that response carries no CORS headers at all, so a fetch from a page
// is refused by the browser and nothing written here would change it.
// Downloading has to happen somewhere without a same-origin policy,
// which leaves this process.
//
// WHY A REPOSITORY AND NOT A URL. This is the first outbound request
// the API server makes on a caller's behalf; every other address it
// fetches -- an OIDC issuer's metadata, a token endpoint -- comes from
// the configuration. An endpoint that fetched a URL a caller supplied
// would be a request forwarder running inside the access point's
// network, where it could reach a daemon's admin port, a cloud
// metadata service, or anything else bound to localhost. So the caller
// names an owner, a repository and a tag, each has to match a pattern,
// and the URL is built here from the pieces. Redirects are followed
// only while they stay on GitHub's own hosts, for the same reason.
//
// Public repositories only. A private one needs a credential, and a
// GitHub token living on the access point is a new secret with its own
// handling, rotation and blast radius; it is not a line item in a
// feature for installing example apps.

// githubAPIBase is GitHub's REST root. A variable so a test can point
// it at a local stub; nothing reassigns it in production.
var githubAPIBase = "https://api.github.com"

const (
	// githubFetchTimeout bounds one install, metadata and bundle
	// together. Generous because a bundle may be large and an access
	// point's egress may be slow, but finite: this runs inside a
	// request, and a hung fetch would hold a connection open.
	githubFetchTimeout = 5 * time.Minute

	// githubMetaBytes bounds the release JSON. A release with a great
	// many assets is still kilobytes; this is here so a hostile or
	// broken answer cannot be read into memory without limit.
	githubMetaBytes = 4 << 20

	// githubSumBytes bounds the checksum sidecar, which is one line.
	githubSumBytes = 4 << 10
)

// The shapes a caller's pieces have to take. These are the security
// boundary rather than a politeness: each one is interpolated into a
// URL this server then fetches.
//
// A tag may not contain a slash. GitHub allows one, but a slash in a
// tag has to be escaped into the API path and the escaping is not
// uniform across GitHub's routes; refusing it costs the rare
// `release/1.0` style tag and removes a whole class of path confusion.
var (
	githubOwnerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	githubRepoPattern  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	githubTagPattern   = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,128}$`)
	githubAssetPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}$`)
)

// githubSource is the release asset a caller asked for.
type githubSource struct {
	Owner string
	Repo  string
	// Tag is empty for "whatever is latest".
	Tag string
	// Asset is empty for "the release's only .zip".
	Asset string
}

// Slug is the repository as it is written and displayed.
func (g githubSource) Slug() string { return g.Owner + "/" + g.Repo }

// parseGitHubSource validates the pieces and assembles them.
//
// A pasted repository URL is accepted and reduced, because that is
// what is on the clipboard after looking at a release page. It is
// reduced and then checked, never trusted for having looked like a
// GitHub URL.
func parseGitHubSource(repo, tag, asset string) (githubSource, error) {
	slug := strings.TrimSpace(repo)
	for _, prefix := range []string{"https://github.com/", "http://github.com/", "github.com/"} {
		slug = strings.TrimPrefix(slug, prefix)
	}
	slug = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(slug), "/"), ".git")

	owner, name, ok := strings.Cut(slug, "/")
	if !ok || owner == "" || name == "" {
		return githubSource{}, fmt.Errorf("name the repository as owner/name, for example bbockelm/htcondor-site-app-template")
	}
	if !githubOwnerPattern.MatchString(owner) {
		return githubSource{}, fmt.Errorf("%q is not a GitHub account name", owner)
	}
	if !githubRepoPattern.MatchString(name) || name == "." || name == ".." {
		return githubSource{}, fmt.Errorf("%q is not a GitHub repository name", name)
	}

	src := githubSource{Owner: owner, Repo: name}

	// "latest" typed by hand means the same as leaving it blank. It is
	// resolved to a real tag before anything is recorded, so that the
	// row says which release is installed rather than repeating the
	// question that was asked.
	src.Tag = strings.TrimSpace(tag)
	if strings.EqualFold(src.Tag, "latest") {
		src.Tag = ""
	}
	if src.Tag != "" {
		if !githubTagPattern.MatchString(src.Tag) || strings.Contains(src.Tag, "..") {
			return githubSource{}, fmt.Errorf("%q is not a tag this can fetch; letters, digits, dot, underscore, plus and hyphen only", src.Tag)
		}
	}

	src.Asset = strings.TrimSpace(asset)
	if src.Asset != "" {
		if !githubAssetPattern.MatchString(src.Asset) || strings.Contains(src.Asset, "..") {
			return githubSource{}, fmt.Errorf("%q is not an asset file name", src.Asset)
		}
	}
	return src, nil
}

// githubHostAllowed reports whether a redirect may be followed to host.
//
// Release assets are served from a storage host under
// githubusercontent.com, and WHICH host has changed over time, so the
// domain suffix is the part worth pinning rather than any one name.
func githubHostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch host {
	case "github.com", "api.github.com", "codeload.github.com":
		return true
	}
	return strings.HasSuffix(host, ".githubusercontent.com")
}

// newGitHubClient is the client used for both the metadata and the
// download. Its redirect policy is the containment: a response that
// tries to send this server anywhere but GitHub is an error, not a
// hop.
func newGitHubClient() *http.Client {
	return &http.Client{
		Timeout: githubFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("too many redirects")
			}
			if !githubAddressOK(req.URL) {
				return fmt.Errorf("refusing a redirect to %s: not a GitHub host", req.URL.Host)
			}
			return nil
		},
	}
}

// githubStubAddr, when set, is a host:port that may also be fetched,
// so a test can drive the download path against a local stub. It is
// an ADDRESS and not a host name because the test that matters points
// two stubs at 127.0.0.1 and tells them apart by port: a redirect from
// one to the other has to be refused. Empty in production.
var githubStubAddr string

// githubAddressOK reports whether an address may be fetched at all.
//
// Scheme and host together, because they are one decision: plaintext
// to a GitHub host is as unacceptable as TLS to somewhere else, and
// splitting them produced an error message that named the host when
// the scheme was the problem.
func githubAddressOK(u *url.URL) bool {
	if githubStubAddr != "" && u.Host == githubStubAddr {
		return true
	}
	return u.Scheme == "https" && githubHostAllowed(u.Hostname())
}

// githubAsset is one file attached to a release.
type githubAsset struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	DownloadURL string `json:"browser_download_url"`
}

// githubRelease is as much of a release as this needs.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	HTMLURL string        `json:"html_url"`
	Assets  []githubAsset `json:"assets"`
}

// resolveGitHubRelease asks GitHub which release is meant and what is
// attached to it.
func resolveGitHubRelease(ctx context.Context, client *http.Client, src githubSource) (githubRelease, error) {
	where := "/releases/latest"
	if src.Tag != "" {
		where = "/releases/tags/" + url.PathEscape(src.Tag)
	}
	endpoint := githubAPIBase + "/repos/" + url.PathEscape(src.Owner) + "/" + url.PathEscape(src.Repo) + where

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return githubRelease{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "htcondor-api")

	resp, err := client.Do(req)
	if err != nil {
		return githubRelease{}, fmt.Errorf("could not reach GitHub: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		// One message for both, deliberately: an unauthenticated
		// caller cannot tell a private repository from a missing one,
		// and neither can this.
		if src.Tag != "" {
			return githubRelease{}, fmt.Errorf("%s has no release tagged %s, or the repository is not public", src.Slug(), src.Tag)
		}
		return githubRelease{}, fmt.Errorf("%s has no published release, or the repository is not public", src.Slug())
	case http.StatusForbidden, http.StatusTooManyRequests:
		return githubRelease{}, fmt.Errorf("GitHub declined the request for %s; its rate limit for unauthenticated callers is per source address, and it resets within the hour", src.Slug())
	default:
		return githubRelease{}, fmt.Errorf("GitHub answered %s for %s", resp.Status, src.Slug())
	}

	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, githubMetaBytes)).Decode(&rel); err != nil {
		return githubRelease{}, fmt.Errorf("could not read GitHub's answer for %s: %w", src.Slug(), err)
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return githubRelease{}, fmt.Errorf("GitHub's answer for %s names no tag", src.Slug())
	}
	return rel, nil
}

// pickGitHubAssets chooses the bundle to install and the checksum that
// attests it.
//
// With no asset named, exactly one .zip is required rather than the
// first one found. A release carrying two bundles is a release where
// guessing would install the wrong app, silently and under a name the
// administrator chose for the other one.
func pickGitHubAssets(rel githubRelease, want string) (bundle githubAsset, sum githubAsset, err error) {
	if want != "" {
		for _, a := range rel.Assets {
			if a.Name == want {
				return a, findGitHubSidecar(rel, a.Name), nil
			}
		}
		return githubAsset{}, githubAsset{}, fmt.Errorf("release %s has no asset named %s%s",
			rel.TagName, want, describeGitHubAssets(rel))
	}

	var zips []githubAsset
	for _, a := range rel.Assets {
		if strings.HasSuffix(strings.ToLower(a.Name), ".zip") {
			zips = append(zips, a)
		}
	}
	switch len(zips) {
	case 1:
		return zips[0], findGitHubSidecar(rel, zips[0].Name), nil
	case 0:
		return githubAsset{}, githubAsset{}, fmt.Errorf("release %s has no .zip attached%s",
			rel.TagName, describeGitHubAssets(rel))
	default:
		names := make([]string, 0, len(zips))
		for _, a := range zips {
			names = append(names, a.Name)
		}
		return githubAsset{}, githubAsset{}, fmt.Errorf("release %s has more than one .zip (%s); name the one to install",
			rel.TagName, strings.Join(names, ", "))
	}
}

// findGitHubSidecar returns the <bundle>.sha256 asset, if the release
// has one. A missing sidecar is not an error: it means the bundle
// arrives unattested, which is what a hand-uploaded one does too.
func findGitHubSidecar(rel githubRelease, bundle string) githubAsset {
	for _, a := range rel.Assets {
		if a.Name == bundle+".sha256" {
			return a
		}
	}
	return githubAsset{}
}

// describeGitHubAssets lists what the release does carry, for an error
// message that says what to do next instead of only what failed.
func describeGitHubAssets(rel githubRelease) string {
	if len(rel.Assets) == 0 {
		return " (it has no assets at all)"
	}
	names := make([]string, 0, len(rel.Assets))
	for _, a := range rel.Assets {
		names = append(names, a.Name)
	}
	return " (it has: " + strings.Join(names, ", ") + ")"
}

// fetchGitHubSidecar reads the checksum asset and returns the hash it
// names.
func fetchGitHubSidecar(ctx context.Context, client *http.Client, a githubAsset) (string, error) {
	if a.DownloadURL == "" {
		return "", nil
	}
	body, err := getGitHubAsset(ctx, client, a)
	if err != nil {
		return "", err
	}
	defer func() { _ = body.Close() }()
	data, err := io.ReadAll(io.LimitReader(body, githubSumBytes))
	if err != nil {
		return "", fmt.Errorf("could not read %s: %w", a.Name, err)
	}
	digest, err := siteapps.ParseDigestSidecar(data)
	if err != nil {
		return "", fmt.Errorf("%s: %w", a.Name, err)
	}
	return digest, nil
}

// getGitHubAsset opens an asset for reading. The caller closes it.
func getGitHubAsset(ctx context.Context, client *http.Client, a githubAsset) (io.ReadCloser, error) {
	if a.DownloadURL == "" {
		return nil, fmt.Errorf("asset %s has no download address", a.Name)
	}
	// The address comes from GitHub's own answer rather than from the
	// caller, but it is checked all the same: it is still a URL from
	// the network, and the redirect policy only sees hops AFTER the
	// first request.
	u, err := url.Parse(a.DownloadURL)
	if err != nil {
		return nil, fmt.Errorf("asset %s has an unreadable address", a.Name)
	}
	if !githubAddressOK(u) {
		return nil, fmt.Errorf("asset %s is hosted at %s, which is not GitHub", a.Name, u.Host)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("User-Agent", "htcondor-api")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not download %s: %w", a.Name, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GitHub answered %s for %s", resp.Status, a.Name)
	}
	return resp.Body, nil
}

// uiError is a refusal written for the administrator reading it.
//
// Capitalized and punctuated on purpose: it is rendered as a sentence
// in the page, not wrapped into a larger error string. A named type
// rather than fmt.Errorf so that intent is stated once here instead of
// as a lint suppression at each site.
type uiError string

func (e uiError) Error() string { return string(e) }

// siteAppBundleSource is where one publish gets its bytes, and what is
// known about where they came from.
type siteAppBundleSource struct {
	// Body is the bundle. The caller closes it.
	Body io.ReadCloser
	// Expect is the SHA-256 the bundle must hash to, empty when
	// nothing attests it.
	Expect string
	// Repo, Ref and Asset are the provenance to record. Empty for a
	// bundle that arrived as a file.
	Repo  string
	Ref   string
	Asset string
}

// Describe names the source for the log line.
func (b siteAppBundleSource) Describe() string {
	if b.Repo == "" {
		return "uploaded file"
	}
	return b.Repo + "@" + b.Ref + " (" + b.Asset + ")"
}

// openBundleSource decides where this request's bundle comes from and
// opens it. The returned status is the one to answer with on error.
func (s *Handler) openBundleSource(r *http.Request) (siteAppBundleSource, int, error) {
	if !strings.EqualFold(strings.TrimSpace(r.FormValue("source")), "github") {
		file, header, err := r.FormFile("bundle")
		if err != nil {
			return siteAppBundleSource{}, http.StatusBadRequest,
				uiError("Attach the bundle as the 'bundle' field")
		}
		if header.Size > maxSiteAppBundleBytes {
			_ = file.Close()
			return siteAppBundleSource{}, http.StatusRequestEntityTooLarge,
				uiError(fmt.Sprintf("The bundle is larger than %d bytes", int64(maxSiteAppBundleBytes)))
		}
		return siteAppBundleSource{Body: file}, http.StatusOK, nil
	}

	if !s.siteAppGitHubAllowed() {
		return siteAppBundleSource{}, http.StatusForbidden,
			uiError("This server does not fetch bundles from GitHub. Download the release asset and attach it instead.")
	}
	src, err := parseGitHubSource(r.FormValue("repo"), r.FormValue("ref"), r.FormValue("asset"))
	if err != nil {
		return siteAppBundleSource{}, http.StatusBadRequest, err
	}

	ctx := r.Context()
	client := newGitHubClient()

	rel, err := resolveGitHubRelease(ctx, client, src)
	if err != nil {
		return siteAppBundleSource{}, http.StatusBadGateway, err
	}
	bundle, sum, err := pickGitHubAssets(rel, src.Asset)
	if err != nil {
		// The release exists and GitHub answered; what is missing is
		// the asset that was asked for, which the caller can fix.
		return siteAppBundleSource{}, http.StatusBadRequest, err
	}
	if bundle.Size > maxSiteAppBundleBytes {
		return siteAppBundleSource{}, http.StatusRequestEntityTooLarge,
			fmt.Errorf("%s is %d bytes, over the %d byte limit", bundle.Name, bundle.Size, int64(maxSiteAppBundleBytes))
	}

	// The checksum first, because it has to be in hand before the
	// bundle is streamed: it is what decides whether those bytes are
	// allowed to become the file an app is served from.
	expect, err := fetchGitHubSidecar(ctx, client, sum)
	if err != nil {
		return siteAppBundleSource{}, http.StatusBadGateway, err
	}
	body, err := getGitHubAsset(ctx, client, bundle)
	if err != nil {
		return siteAppBundleSource{}, http.StatusBadGateway, err
	}
	return siteAppBundleSource{
		Body:   body,
		Expect: expect,
		Repo:   src.Slug(),
		// The resolved tag, not what was asked for: "latest" is a
		// question and this is the answer.
		Ref:   rel.TagName,
		Asset: bundle.Name,
	}, http.StatusOK, nil
}
