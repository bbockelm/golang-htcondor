package httpserver

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func TestWriteWatchSSEUpsert(t *testing.T) {
	rec := httptest.NewRecorder()
	ad := classad.New()
	ad.InsertAttrString("Name", "slot1@host")
	ad.InsertAttr("Cpus", 8)

	cursor := []byte{0x01, 0x02, 0x03}
	key := "slot1@host\x00<1.2.3.4:9618>"
	if err := writeWatchSSE(rec, rec, "upsert", watchKeyString(key), ad, cursor, ""); err != nil {
		t.Fatalf("writeWatchSSE: %v", err)
	}
	out := rec.Body.String()

	if !strings.Contains(out, "event: upsert\n") {
		t.Errorf("missing event line:\n%s", out)
	}
	if want := "id: " + base64.StdEncoding.EncodeToString(cursor) + "\n"; !strings.Contains(out, want) {
		t.Errorf("missing/incorrect id line (want %q):\n%s", want, want)
	}
	// The key is base64 (JSON-safe even though it has a NUL); the ad is embedded.
	if !strings.Contains(out, base64.StdEncoding.EncodeToString([]byte(key))) {
		t.Errorf("key not base64-encoded in data:\n%s", out)
	}
	if !strings.Contains(out, `"Name"`) || !strings.Contains(out, "slot1@host") {
		t.Errorf("ad not embedded in data:\n%s", out)
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Errorf("SSE frame not terminated by blank line:\n%q", out)
	}
}

func TestWriteWatchSSEDeleteNoCursor(t *testing.T) {
	rec := httptest.NewRecorder()
	if err := writeWatchSSE(rec, rec, "delete", watchKeyString("k"), nil, nil, ""); err != nil {
		t.Fatal(err)
	}
	out := rec.Body.String()
	if strings.Contains(out, "id:") {
		t.Errorf("delete with no cursor should have no id line:\n%s", out)
	}
	if !strings.Contains(out, "event: delete\n") {
		t.Errorf("missing event line:\n%s", out)
	}
}

func TestCursorFromRequest(t *testing.T) {
	cur := []byte("resume-cursor-bytes")
	enc := base64.StdEncoding.EncodeToString(cur)

	// Last-Event-ID header.
	r := httptest.NewRequest("GET", "/api/v1/collector/watch", nil)
	r.Header.Set("Last-Event-ID", enc)
	if got := cursorFromRequest(r); string(got) != string(cur) {
		t.Errorf("Last-Event-ID: got %q want %q", got, cur)
	}

	// ?cursor= query fallback.
	r2 := httptest.NewRequest("GET", "/api/v1/collector/watch?cursor="+enc, nil)
	if got := cursorFromRequest(r2); string(got) != string(cur) {
		t.Errorf("?cursor: got %q want %q", got, cur)
	}

	// Absent -> nil (full replay).
	r3 := httptest.NewRequest("GET", "/api/v1/collector/watch", nil)
	if got := cursorFromRequest(r3); got != nil {
		t.Errorf("absent cursor: got %q want nil", got)
	}
}

func TestSSEKind(t *testing.T) {
	for in, want := range map[string]string{"Upsert": "upsert", "Delete": "delete", "GoingAway": "goingaway"} {
		if got := sseKind(in); got != want {
			t.Errorf("sseKind(%q) = %q, want %q", in, got, want)
		}
	}
}
