// Package jobid is the one place a job's identity becomes text and text
// becomes a job's identity.
//
// A job is identified by the triple (schedd, cluster, proc). Every layer
// passes the ID value around; only a Codec renders it as a single token,
// and only where a human or a protocol forces one (a URL path segment, an
// SSH username, a web UI route). Wire formats and durable state carry the
// three fields separately, so the textual form can change without a
// migration.
package jobid

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// ID identifies one job.
type ID struct {
	// Schedd is the schedd's Name as advertised. Empty means the ID is
	// incomplete: it names a cluster.proc without saying on which access
	// point, which is all a single-AP deployment ever needs.
	Schedd  string
	Cluster int64
	Proc    int64
}

// Complete reports whether the ID names its schedd.
func (id ID) Complete() bool { return id.Schedd != "" }

// Local is the ID without its schedd. The schedd half is what an
// incomplete ID leaves open, so a lookup that resolves one compares on
// this.
func (id ID) Local() ID { return ID{Cluster: id.Cluster, Proc: id.Proc} }

// WithSchedd returns the ID completed with schedd.
func (id ID) WithSchedd(schedd string) ID {
	id.Schedd = schedd
	return id
}

// Codec renders an ID as a single token and parses one back.
//
// Parse accepts an incomplete ID -- "123.0", or a bare cluster "123",
// which names proc 0 -- and returns it with Schedd empty. Format of an
// incomplete ID renders only cluster.proc.
type Codec interface {
	Format(ID) string
	Parse(string) (ID, error)
}

// ErrSyntax is wrapped by every Parse failure.
var ErrSyntax = errors.New("invalid job id")

// DefaultCodecName is the codec used when none is configured.
const DefaultCodecName = "at"

var (
	registryMu sync.RWMutex
	registry   = map[string]Codec{}
)

func init() {
	Register(DefaultCodecName, AtCodec{})
}

// Register adds a codec under name (HTTP_API_JOB_ID_CODEC selects it),
// replacing any codec of that name. It panics on an empty name: a codec
// nobody can select is a bug.
func Register(name string, c Codec) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" || c == nil {
		panic("jobid: Register with an empty codec name")
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[name] = c
}

// Lookup returns the codec registered under name (case-insensitive). An
// empty name selects the default codec.
func Lookup(name string) (Codec, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		name = DefaultCodecName
	}
	registryMu.RLock()
	defer registryMu.RUnlock()
	c, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("unknown job id codec %q (known: %s)", name, strings.Join(namesLocked(), ", "))
	}
	return c, nil
}

// Default returns the default codec.
func Default() Codec {
	c, err := Lookup(DefaultCodecName)
	if err != nil {
		// The default registers itself in init; reaching this is a bug.
		panic(err)
	}
	return c
}

// Names lists the registered codecs, sorted.
func Names() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return namesLocked()
}

func namesLocked() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// AtCodec renders "123.0@ap40.example.org".
//
//   - It splits at the FIRST "@": a schedd name may itself contain "@"
//     ("jobs@ap40.example.org"), while cluster.proc never does.
//   - It needs no escaping in a URL path segment.
//   - It survives as an SSH username, because OpenSSH splits user@host at
//     the LAST "@".
type AtCodec struct{}

// Format implements Codec.
func (AtCodec) Format(id ID) string {
	local := strconv.FormatInt(id.Cluster, 10) + "." + strconv.FormatInt(id.Proc, 10)
	if id.Schedd == "" {
		return local
	}
	return local + "@" + id.Schedd
}

// Parse implements Codec.
func (AtCodec) Parse(s string) (ID, error) {
	local, schedd, hasSchedd := strings.Cut(s, "@")
	if hasSchedd {
		if err := ValidSchedd(schedd); err != nil {
			return ID{}, fmt.Errorf("%w %q: %w", ErrSyntax, s, err)
		}
	}
	clusterText, procText, hasProc := strings.Cut(local, ".")
	cluster, err := parseNumber(clusterText)
	if err != nil {
		return ID{}, fmt.Errorf("%w %q: cluster: %w", ErrSyntax, s, err)
	}
	var proc int64
	if hasProc {
		if proc, err = parseNumber(procText); err != nil {
			return ID{}, fmt.Errorf("%w %q: proc: %w", ErrSyntax, s, err)
		}
	}
	return ID{Schedd: schedd, Cluster: cluster, Proc: proc}, nil
}

// parseNumber accepts a non-negative decimal integer in canonical form:
// ASCII digits only, no sign, no whitespace, no leading zero (except "0"
// itself), and no overflow. strconv alone would accept "+5" and, in
// ParseInt, a leading "-"; a lenient grammar is how two spellings of one
// job end up as two cache keys.
func parseNumber(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("%q is not a decimal number", s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("%q has a leading zero", s)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is out of range", s)
	}
	return n, nil
}

// ValidSchedd reports why name cannot be a schedd in a job id, or nil.
//
// It rejects only what cannot survive as one token: empty, whitespace or
// control characters, and the characters that end a URL path segment.
// It does not otherwise police schedd names -- those are the collector's
// business.
func ValidSchedd(name string) error {
	if name == "" {
		return errors.New("empty schedd name")
	}
	for i := 0; i < len(name); i++ {
		switch c := name[i]; {
		case c <= ' ' || c == 0x7f:
			return fmt.Errorf("schedd name contains a space or control character")
		case c == '/' || c == '?' || c == '#' || c == '%' || c == '\\':
			return fmt.Errorf("schedd name contains %q", c)
		}
	}
	return nil
}

// Valid reports why id cannot be rendered and parsed back, or nil.
func Valid(id ID) error {
	if id.Cluster < 0 || id.Proc < 0 {
		return fmt.Errorf("negative cluster or proc in %d.%d", id.Cluster, id.Proc)
	}
	if id.Schedd != "" {
		return ValidSchedd(id.Schedd)
	}
	return nil
}
