package apassign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// The rest backend: a site service answers.
//
//	GET {HTTP_API_AP_ASSIGNMENT_REST_URL}/v1/assignment?user=alice%40example.org&subject=...&kind=job[&group=...]
//	Authorization: Bearer <contents of HTTP_API_AP_ASSIGNMENT_REST_TOKEN_FILE>
//
//	200 {"schedd":"ap12.example.org","alternates":["ap13.example.org"],"ttl_seconds":300}
//	404 -> no answer (the next backend is asked)
//	403 -> denied (the user may not submit)
//
// Anything else -- another status, a timeout, a body that is not that
// JSON or is larger than RESTMaxBody -- is an error, which the chain does
// not fall through.

// DefaultRESTTTL is how long a rest answer that states no TTL is reused.
const DefaultRESTTTL = 300 * time.Second

// RESTMaxBody bounds the response read from the service.
const RESTMaxBody = 64 << 10

// restAnswer is the 200 body.
type restAnswer struct {
	Schedd     string   `json:"schedd"`
	Alternates []string `json:"alternates"`
	TTLSeconds int64    `json:"ttl_seconds"`
}

// REST is the rest backend.
type REST struct {
	endpoint  *url.URL
	tokenFile string
	client    *http.Client

	mu       sync.Mutex
	token    string
	tokenMod time.Time
	tokenSz  int64
}

// RESTOptions tunes a REST backend.
type RESTOptions struct {
	// Client replaces the HTTP client (tests: a TLS test server's).
	// Redirects are never followed, whatever the client says.
	Client *http.Client
}

// NewREST builds the backend. The URL must be https, except to a
// loopback address: the request carries a bearer token. A token file
// that is named but cannot be read is an error.
func NewREST(rawURL, tokenFile string, opts RESTOptions) (*REST, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("the rest access point assignment backend needs HTTP_API_AP_ASSIGNMENT_REST_URL")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("HTTP_API_AP_ASSIGNMENT_REST_URL %q is not an absolute URL", rawURL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("HTTP_API_AP_ASSIGNMENT_REST_URL %q must use https: the request carries a bearer token "+
				"(plain http is accepted only to a loopback address)", rawURL)
		}
	default:
		return nil, fmt.Errorf("HTTP_API_AP_ASSIGNMENT_REST_URL %q must be an https URL", rawURL)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("HTTP_API_AP_ASSIGNMENT_REST_URL %q must not carry a query or fragment", rawURL)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/v1/assignment"
	u.RawPath = ""

	var client http.Client
	if opts.Client != nil {
		client = *opts.Client
	}
	if client.Timeout <= 0 || client.Timeout > DefaultTimeout {
		client.Timeout = DefaultTimeout
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	r := &REST{endpoint: u, tokenFile: strings.TrimSpace(tokenFile), client: &client}
	if r.tokenFile != "" {
		if _, err := r.bearer(); err != nil {
			return nil, fmt.Errorf("HTTP_API_AP_ASSIGNMENT_REST_TOKEN_FILE: %w", err)
		}
	}
	return r, nil
}

func loopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// bearer returns the token file's contents, re-read when the file
// changes.
func (r *REST) bearer() (string, error) {
	if r.tokenFile == "" {
		return "", nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	info, err := os.Stat(r.tokenFile)
	if err != nil {
		return "", err
	}
	if r.token != "" && info.ModTime().Equal(r.tokenMod) && info.Size() == r.tokenSz {
		return r.token, nil
	}
	b, err := os.ReadFile(r.tokenFile)
	if err != nil {
		return "", err
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", fmt.Errorf("%s is empty", r.tokenFile)
	}
	r.token, r.tokenMod, r.tokenSz = tok, info.ModTime(), info.Size()
	return tok, nil
}

// Reload forgets the cached token, so the next request re-reads it.
func (r *REST) Reload() error {
	r.mu.Lock()
	r.token = ""
	r.mu.Unlock()
	_, err := r.bearer()
	return err
}

// Assign implements Assigner.
func (r *REST) Assign(ctx context.Context, req Request) (Assignment, error) {
	u := *r.endpoint
	q := url.Values{}
	q.Set("user", req.User)
	q.Set("subject", req.Subject)
	q.Set("kind", req.Kind)
	for _, g := range req.Groups {
		q.Add("group", g)
	}
	u.RawQuery = q.Encode()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Assignment{}, err
	}
	hreq.Header.Set("Accept", "application/json")
	tok, err := r.bearer()
	if err != nil {
		return Assignment{}, fmt.Errorf("reading the token file: %w", err)
	}
	if tok != "" {
		hreq.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := r.client.Do(hreq)
	if err != nil {
		return Assignment{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, RESTMaxBody))
		_ = resp.Body.Close()
	}()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return Assignment{}, ErrNoAnswer
	case http.StatusForbidden:
		return Assignment{}, ErrDenied
	default:
		return Assignment{}, fmt.Errorf("the assignment service answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, RESTMaxBody+1))
	if err != nil {
		return Assignment{}, fmt.Errorf("reading the assignment service's answer: %w", err)
	}
	if len(body) > RESTMaxBody {
		return Assignment{}, fmt.Errorf("the assignment service's answer is over %d bytes", RESTMaxBody)
	}
	var ans restAnswer
	if err := json.Unmarshal(body, &ans); err != nil {
		return Assignment{}, fmt.Errorf("the assignment service's answer is not the expected JSON: %w", err)
	}
	if strings.TrimSpace(ans.Schedd) == "" {
		return Assignment{}, errors.New("the assignment service's answer names no schedd")
	}
	a := Assignment{Schedd: strings.TrimSpace(ans.Schedd)}
	for _, alt := range ans.Alternates {
		if alt = strings.TrimSpace(alt); alt != "" {
			a.Alternates = append(a.Alternates, alt)
		}
	}
	if ans.TTLSeconds > 0 {
		a.TTL = time.Duration(min(ans.TTLSeconds, int64(MaxTTL/time.Second))) * time.Second
	}
	return a, nil
}
