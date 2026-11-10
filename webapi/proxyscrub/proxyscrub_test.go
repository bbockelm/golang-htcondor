package proxyscrub

import (
	"context"
	"net/http"
	"reflect"
	"testing"
)

func TestRequestStripsCredentialsAndKeepsTheRest(t *testing.T) {
	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := r.Header
	h.Add("Cookie", "htcondor_session=secret; other=x")
	h.Add("Cookie", "idp_session=s2;  htcondor_api_last_account=a ;jobs=y")
	h.Set("Authorization", "Bearer t")
	h.Set("Proxy-Authorization", "Basic dTpw")
	h.Set("Forwarded", "for=192.0.2.1;host=example.com")
	h.Set("X-Forwarded-For", "192.0.2.1")
	h.Set("X-Forwarded-User", "alice")
	h.Set("X-Forwarded-Access-Token", "tok")
	h.Set("X-Auth-Request-Email", "alice@example.com")
	h.Set("X-Amzn-Oidc-Accesstoken", "tok")
	h.Set("X-Real-Ip", "192.0.2.1")
	h.Set("X-Site-User", "alice")
	h.Set("X-Forwarded-Host", "public.example.com")
	h.Set("X-Forwarded-Proto", "https")
	h.Set("Connection", "Upgrade")
	h.Set("Upgrade", "websocket")
	h.Set("X-Xsrftoken", "abc")

	New("X-Site-User").Request(r)

	for _, name := range []string{
		"Authorization", "Proxy-Authorization", "Forwarded",
		"X-Forwarded-User", "X-Forwarded-Access-Token", "X-Auth-Request-Email",
		"X-Amzn-Oidc-Accesstoken", "X-Real-Ip", "X-Site-User",
	} {
		if v, ok := h[name]; ok {
			t.Errorf("%s survived: %q", name, v)
		}
	}
	if v, ok := h["X-Forwarded-For"]; !ok || v != nil {
		t.Errorf("X-Forwarded-For = %q (present %v), want present and nil so ReverseProxy adds nothing", v, ok)
	}
	if got, want := h.Values("Cookie"), []string{"other=x", "jobs=y"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Cookie = %q, want %q", got, want)
	}
	for name, want := range map[string]string{
		"X-Forwarded-Host":  "public.example.com",
		"X-Forwarded-Proto": "https",
		"Connection":        "Upgrade",
		"Upgrade":           "websocket",
		"X-Xsrftoken":       "abc",
	} {
		if got := h.Get(name); got != want {
			t.Errorf("%s = %q, want %q kept", name, got, want)
		}
	}
}

func TestRequestDropsCookieHeaderWhenOnlyOursWereThere(t *testing.T) {
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://example.com/", nil)
	r.Header.Set("Cookie", "htcondor_session=secret")
	var s *Scrubber
	s.Request(r)
	if v, ok := r.Header["Cookie"]; ok {
		t.Errorf("Cookie = %q, want the header gone", v)
	}
}

func TestResponseDropsOurSetCookie(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "htcondor_session=fixed; Path=/; HttpOnly")
	resp.Header.Add("Set-Cookie", " idp_session=x")
	resp.Header.Add("Set-Cookie", "htcondor_api_last_account=y; Path=/")
	resp.Header.Add("Set-Cookie", "_xsrf=abc; Path=/api/v1/jobs/1.0/proxy/8888/")

	if err := New().Response(resp); err != nil {
		t.Fatal(err)
	}
	if got, want := resp.Header.Values("Set-Cookie"), []string{"_xsrf=abc; Path=/api/v1/jobs/1.0/proxy/8888/"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Set-Cookie = %q, want %q", got, want)
	}
}
