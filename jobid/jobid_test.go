package jobid

import (
	"errors"
	"strings"
	"testing"
)

func TestAtCodecParse(t *testing.T) {
	c := AtCodec{}
	cases := []struct {
		in   string
		want ID
	}{
		{"123.0@ap40.example.org", ID{Schedd: "ap40.example.org", Cluster: 123, Proc: 0}},
		{"1.2@ap1", ID{Schedd: "ap1", Cluster: 1, Proc: 2}},
		{"0.0@x", ID{Schedd: "x", Cluster: 0, Proc: 0}},
		// The schedd name keeps every "@" after the first.
		{"5.1@jobs@ap40.example.org", ID{Schedd: "jobs@ap40.example.org", Cluster: 5, Proc: 1}},
		{"5.1@a@b@c", ID{Schedd: "a@b@c", Cluster: 5, Proc: 1}},
		// Incomplete ids.
		{"123.0", ID{Cluster: 123, Proc: 0}},
		{"123.45", ID{Cluster: 123, Proc: 45}},
		{"123", ID{Cluster: 123, Proc: 0}},
		{"9223372036854775807.9223372036854775807@ap", ID{Schedd: "ap", Cluster: 9223372036854775807, Proc: 9223372036854775807}},
		// Uppercase and punctuation a hostname may carry.
		{"7.3@AP-7_x.Example.ORG:9618", ID{Schedd: "AP-7_x.Example.ORG:9618", Cluster: 7, Proc: 3}},
	}
	for _, tc := range cases {
		got, err := c.Parse(tc.in)
		if err != nil {
			t.Errorf("Parse(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Parse(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
		if got.Complete() != (tc.want.Schedd != "") {
			t.Errorf("Parse(%q).Complete() = %v", tc.in, got.Complete())
		}
	}
}

func TestAtCodecParseRejects(t *testing.T) {
	c := AtCodec{}
	bad := []string{
		"",
		"@ap1",
		"123.0@",                   // empty schedd
		"+5.0@ap1",                 // sign
		"-5.0@ap1",                 // sign
		"5.-1@ap1",                 // sign
		"5.+1@ap1",                 // sign
		" 5.0@ap1",                 // whitespace
		"5.0 @ap1",                 // whitespace
		"5 .0@ap1",                 // whitespace
		"5.0@ap 1",                 // whitespace in schedd
		"5.0@ap1\n",                // control in schedd
		"5.0@\tap1",                // control in schedd
		"5.0\x00@ap1",              // NUL
		"5.@ap1",                   // empty proc
		".0@ap1",                   // empty cluster
		"5.0.1@ap1",                // extra dot
		"05.0@ap1",                 // leading zero
		"5.00@ap1",                 // leading zero
		"0x5.0@ap1",                // hex
		"5e2.0@ap1",                // exponent
		"1_000.0@ap1",              // Go digit separator
		"５.0@ap1",                  // fullwidth digit
		"5.0@ap/1",                 // path separator
		"5.0@ap?x=1",               // query
		"5.0@ap#x",                 // fragment
		"5.0@ap%2F1",               // percent escape
		"5.0@ap\\1",                // backslash
		"9223372036854775808.0@ap", // overflow
		"1.9223372036854775808@ap", // overflow
		"abc",
		"abc@ap1",
		"5.0x@ap1",
	}
	for _, s := range bad {
		if id, err := c.Parse(s); err == nil {
			t.Errorf("Parse(%q) = %+v, want an error", s, id)
		} else if !errors.Is(err, ErrSyntax) {
			t.Errorf("Parse(%q) error %v does not wrap ErrSyntax", s, err)
		}
	}
}

func TestAtCodecFormat(t *testing.T) {
	c := AtCodec{}
	cases := []struct {
		id   ID
		want string
	}{
		{ID{Schedd: "ap40.example.org", Cluster: 123}, "123.0@ap40.example.org"},
		{ID{Schedd: "jobs@ap40", Cluster: 5, Proc: 1}, "5.1@jobs@ap40"},
		{ID{Cluster: 7, Proc: 2}, "7.2"},
	}
	for _, tc := range cases {
		if got := c.Format(tc.id); got != tc.want {
			t.Errorf("Format(%+v) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestRegistry(t *testing.T) {
	c, err := Lookup("")
	if err != nil {
		t.Fatalf("Lookup(\"\"): %v", err)
	}
	if _, ok := c.(AtCodec); !ok {
		t.Errorf("default codec is %T, want AtCodec", c)
	}
	if c, err := Lookup(" AT "); err != nil || c == nil {
		t.Errorf("Lookup is not case/space-insensitive: %v", err)
	}
	if _, err := Lookup("nope"); err == nil || !strings.Contains(err.Error(), "at") {
		t.Errorf("Lookup(nope) = %v, want an error naming the known codecs", err)
	}

	Register("test-hash", hashCodec{})
	got, err := Lookup("test-hash")
	if err != nil {
		t.Fatalf("Lookup(test-hash): %v", err)
	}
	id := ID{Schedd: "ap1", Cluster: 9, Proc: 3}
	if back, err := got.Parse(got.Format(id)); err != nil || back != id {
		t.Errorf("registered codec round trip = %+v, %v", back, err)
	}
	found := false
	for _, n := range Names() {
		found = found || n == "test-hash"
	}
	if !found {
		t.Errorf("Names() = %v, missing test-hash", Names())
	}

	defer func() {
		if recover() == nil {
			t.Error("Register with an empty name must panic")
		}
	}()
	Register(" ", hashCodec{})
}

// hashCodec is a second codec, to prove callers are not hard-wired to "@".
type hashCodec struct{}

func (hashCodec) Format(id ID) string {
	return id.Schedd + "~" + AtCodec{}.Format(id.Local())
}

func (hashCodec) Parse(s string) (ID, error) {
	schedd, local, ok := strings.Cut(s, "~")
	if !ok {
		return AtCodec{}.Parse(s)
	}
	id, err := AtCodec{}.Parse(local)
	return id.WithSchedd(schedd), err
}

func TestValid(t *testing.T) {
	if err := Valid(ID{Schedd: "ap", Cluster: 1}); err != nil {
		t.Errorf("Valid: %v", err)
	}
	for _, id := range []ID{{Cluster: -1}, {Proc: -1}, {Schedd: "a b"}} {
		if Valid(id) == nil {
			t.Errorf("Valid(%+v) = nil, want an error", id)
		}
	}
}

// FuzzAtCodecRoundTrip checks Format then Parse is the identity on every
// valid ID, and that Parse of arbitrary text either fails or yields an ID
// that formats back to text which parses to the same ID.
func FuzzAtCodecRoundTrip(f *testing.F) {
	f.Add("ap40.example.org", int64(123), int64(0))
	f.Add("jobs@ap40", int64(5), int64(1))
	f.Add("", int64(7), int64(2))
	f.Add("a@b@c", int64(0), int64(9223372036854775807))
	c := AtCodec{}
	f.Fuzz(func(t *testing.T, schedd string, cluster, proc int64) {
		id := ID{Schedd: schedd, Cluster: cluster, Proc: proc}
		if Valid(id) != nil {
			// Not representable: Parse must reject what Format renders,
			// never return a different job.
			if back, err := c.Parse(c.Format(id)); err == nil && back == id {
				t.Fatalf("invalid id %+v round-tripped", id)
			}
			return
		}
		text := c.Format(id)
		back, err := c.Parse(text)
		if err != nil {
			t.Fatalf("Parse(Format(%+v)) = %q: %v", id, text, err)
		}
		if back != id {
			t.Fatalf("round trip %+v -> %q -> %+v", id, text, back)
		}
	})
}

// FuzzAtCodecParse feeds arbitrary text to Parse.
func FuzzAtCodecParse(f *testing.F) {
	for _, s := range []string{"123.0@ap", "123", "1.2@a@b", "+5.0@x", "05.0@x", "5.0@"} {
		f.Add(s)
	}
	c := AtCodec{}
	f.Fuzz(func(t *testing.T, s string) {
		id, err := c.Parse(s)
		if err != nil {
			return
		}
		if Valid(id) != nil {
			t.Fatalf("Parse(%q) returned an invalid id %+v", s, id)
		}
		again, err := c.Parse(c.Format(id))
		if err != nil || again != id {
			t.Fatalf("Parse(%q) = %+v, which does not round trip (%+v, %v)", s, id, again, err)
		}
	})
}
