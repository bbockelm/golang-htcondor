package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/bbockelm/golang-htcondor/webapi/httpserver/appdb"
	"golang.org/x/crypto/bcrypt"
)

// Cheaper stand-ins for the startup work in setup_seams.go, installed by
// TestMain. Each produces what the real step would, at a fraction of
// the cost; what a test can observe about the result is unchanged.

func installTestSetupSeams() {
	// The cost is recorded in the hash, so every comparison is as cheap
	// as the hashing; a wrong secret still fails to match.
	secretHashCost = bcrypt.MinCost
	generateSigningKey = pooledSigningKey
	seedAppDB = seedMigratedAppDB
}

// signingKeyPoolSize is how many distinct signing keys the tests use.
// Keys are handed out in turn, so any two providers made within this
// many of each other -- every pair a single test builds -- hold
// different keys.
const signingKeyPoolSize = 16

var signingKeyPool struct {
	mu   sync.Mutex
	der  [][]byte
	next int
}

// pooledSigningKey generates the first signingKeyPoolSize keys and then
// cycles through them. Each caller gets its own parsed copy, so no two
// providers share a key value in memory.
func pooledSigningKey() (*rsa.PrivateKey, error) {
	p := &signingKeyPool
	p.mu.Lock()
	if len(p.der) < signingKeyPoolSize {
		p.mu.Unlock()
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		p.mu.Lock()
		p.der = append(p.der, x509.MarshalPKCS1PrivateKey(key))
		p.mu.Unlock()
		return key, nil
	}
	der := p.der[p.next%len(p.der)]
	p.next++
	p.mu.Unlock()
	return x509.ParsePKCS1PrivateKey(der)
}

// migratedAppDBTemplate is an application database with every
// migration applied and nothing else, built once per test binary.
var migratedAppDBTemplate struct {
	once sync.Once
	data []byte
	err  error
}

func migratedAppDBBytes() ([]byte, error) {
	t := &migratedAppDBTemplate
	t.once.Do(func() {
		dir, err := os.MkdirTemp("", "httpserver-appdb-template-*")
		if err != nil {
			t.err = err
			return
		}
		defer func() { _ = os.RemoveAll(dir) }()
		path := filepath.Join(dir, "app.db")
		db, err := appdb.Open(path)
		if err != nil {
			t.err = err
			return
		}
		t.err = appdb.Migrate(context.Background(), db)
		// Closing checkpoints the journal into the main file, which is
		// then the whole database.
		if cerr := db.Close(); t.err == nil {
			t.err = cerr
		}
		if t.err == nil {
			t.data, t.err = os.ReadFile(path) //nolint:gosec // G304: our own temp file
		}
	})
	return t.data, t.err
}

// seedMigratedAppDB writes the migrated template at path when nothing is
// there yet (or only an empty file, which SQLite treats as a new
// database), so the server's own Migrate finds every migration already
// applied. Anything else -- an existing database, a missing directory,
// a URI rather than a file name -- is left for Open to deal with as it
// would in production; so is any failure here.
func seedMigratedAppDB(path string) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "?#") {
		return
	}
	data, err := migratedAppDBBytes()
	if err != nil {
		return
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }()
	name := filepath.Base(path)
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	fi, err := f.Stat()
	if err != nil || fi.Size() != 0 {
		_ = f.Close()
		return
	}
	if _, err := f.Write(data); err != nil {
		// Back to the empty file Open would have started from.
		_ = f.Truncate(0)
	}
	_ = f.Close()
}
