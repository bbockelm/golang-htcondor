package httpserver

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/bbockelm/golang-htcondor/droppriv"
	"github.com/bbockelm/golang-htcondor/logging"
)

// defaultCertReloadInterval is how often a serving certificate is
// re-read from disk. Certificates are renewed on the order of days, so
// this only needs to be short enough that a renewal takes effect without
// anyone thinking about it; five minutes costs two small file reads.
const defaultCertReloadInterval = 5 * time.Minute

// certReloader serves the current TLS keypair, re-reading it from disk as
// it changes so a renewed certificate takes effect without restarting the
// daemon.
//
// The swap is all-or-nothing, which is the part that matters. A renewal
// writes the certificate and the key as two separate files, so a read
// landing between the two writes sees a new certificate with the old key
// (or half a PEM). tls.X509KeyPair rejects both -- it checks that the
// private key matches the certificate's public key -- and this keeps
// serving the keypair it already had rather than installing anything
// partial. The next interval tries again, so a genuinely mid-write
// renewal costs one cycle of staleness, not a broken listener.
//
// It is deliberately not driven by mtime: comparing the bytes it read
// against the bytes it is serving answers the same question without
// depending on filesystem timestamp granularity or on stat being
// permitted where a read is.
type certReloader struct {
	certFile string
	keyFile  string
	interval time.Duration
	logger   *logging.Logger

	// now is injectable so tests do not have to sleep through an
	// interval.
	now func() time.Time

	mu        sync.RWMutex
	cert      *tls.Certificate
	certPEM   []byte
	keyPEM    []byte
	lastCheck time.Time
}

// newCertReloader loads the keypair once, failing if it cannot: a daemon
// that cannot serve HTTPS at startup should say so rather than come up
// and refuse every connection.
func newCertReloader(certFile, keyFile string, interval time.Duration, logger *logging.Logger) (*certReloader, error) {
	if interval <= 0 {
		interval = defaultCertReloadInterval
	}
	r := &certReloader{
		certFile: certFile,
		keyFile:  keyFile,
		interval: interval,
		logger:   logger,
		now:      time.Now,
	}
	certPEM, keyPEM, cert, err := r.read()
	if err != nil {
		return nil, err
	}
	r.cert, r.certPEM, r.keyPEM, r.lastCheck = cert, certPEM, keyPEM, r.now()
	return r, nil
}

// read loads and parses the keypair without touching the served state.
func (r *certReloader) read() ([]byte, []byte, *tls.Certificate, error) {
	certPEM, err := droppriv.ReadFileMaybeAsRoot(r.certFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading TLS certificate %s: %w", r.certFile, err)
	}
	keyPEM, err := droppriv.ReadFileMaybeAsRoot(r.keyFile)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading TLS key %s: %w", r.keyFile, err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parsing TLS keypair (%s, %s): %w", r.certFile, r.keyFile, err)
	}
	return certPEM, keyPEM, &cert, nil
}

// GetCertificate is the tls.Config hook. It answers from the cached
// keypair, checking the files at most once per interval.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	cert, last := r.cert, r.lastCheck
	r.mu.RUnlock()

	if r.now().Sub(last) < r.interval {
		return cert, nil
	}
	return r.refresh(), nil
}

// refresh re-reads the files and swaps the keypair if it changed and
// parses. It never returns an error: a handshake in progress is served
// with the keypair already in hand, because failing it would turn a
// renewal glitch into an outage.
func (r *certReloader) refresh() *tls.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Another handshake may have refreshed while this one waited.
	if r.now().Sub(r.lastCheck) < r.interval {
		return r.cert
	}
	r.lastCheck = r.now()

	certPEM, keyPEM, cert, err := r.read()
	if err != nil {
		// Half-written, mismatched, or briefly unreadable: keep serving
		// what works and look again next interval.
		if r.logger != nil {
			r.logger.Warn(logging.DestinationHTTP,
				"TLS keypair could not be reloaded; continuing with the one in use",
				"cert", r.certFile, "key", r.keyFile, "error", err.Error())
		}
		return r.cert
	}
	if bytes.Equal(certPEM, r.certPEM) && bytes.Equal(keyPEM, r.keyPEM) {
		return r.cert
	}

	r.cert, r.certPEM, r.keyPEM = cert, certPEM, keyPEM
	if r.logger != nil {
		r.logger.Info(logging.DestinationHTTP, "TLS keypair reloaded",
			"cert", r.certFile, "key", r.keyFile)
	}
	return r.cert
}
