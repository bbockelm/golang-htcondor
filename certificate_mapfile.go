package htcondor

import (
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbockelm/golang-htcondor/config"
	"github.com/bbockelm/golang-htcondor/mapfile"
)

// sciTokensMapMethod is the map file method of a SciToken's authenticated
// name, "issuer,subject".
const sciTokensMapMethod = "SCITOKENS"

// certMapKey names one reading of CERTIFICATE_MAPFILE: the file and the
// options it is read with.
type certMapKey struct {
	path      string
	regexKeys bool
	// exclude is LOCAL_CONFIG_DIR_EXCLUDE_REGEXP, for directories named by
	// @include.
	exclude string
}

// certMapStamp is what a reload compares to tell that the map file changed.
type certMapStamp struct {
	modTime time.Time
	size    int64
}

// certMapEntry is a loaded map file. mf is nil when it could not be read.
type certMapEntry struct {
	mu     sync.Mutex
	loaded bool
	gen    uint64
	stamp  certMapStamp
	mf     *mapfile.MapFile
}

var (
	// certMapGeneration counts ReloadCertificateMapFile calls; an entry
	// loaded under an older generation is read again.
	certMapGeneration atomic.Uint64
	// certMapFiles holds the loaded map files by certMapKey.
	certMapFiles sync.Map
)

// ReloadCertificateMapFile makes the next mapping re-read CERTIFICATE_MAPFILE
// and the files it includes, as HTCondor does on reconfig
// (Authentication::reconfigMapFile). daemon.Daemon calls it on SIGHUP. The
// file is also re-read whenever its modification time or size changes.
func ReloadCertificateMapFile() {
	certMapGeneration.Add(1)
}

// SciTokensMapper returns a security.SecurityConfig.SciTokensMapper backed by
// the SCITOKENS lines of CERTIFICATE_MAPFILE in the config cfg returns, read
// as HTCondor reads it: every principal is a regular expression unless
// CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS is true, and @include is honored. cfg
// is called on each mapping, so a daemon can pass its live config. With no
// CERTIFICATE_MAPFILE, or one that cannot be read, nothing is mapped. The
// mapped name is returned as written; cedar splits it at its last '@' and
// gives a name without one the UID domain.
//
// A canonicalization starting with "PLUGIN:" names a SciTokens plugin, which
// is not supported, so it maps nothing.
func SciTokensMapper(cfg func() *config.Config) func(authName string) (string, bool) {
	return func(authName string) (string, bool) {
		key, ok := certificateMapFileKey(cfg())
		if !ok {
			return "", false
		}
		user, ok := loadCertificateMapFile(key).Map(sciTokensMapMethod, authName)
		if !ok || user == "" {
			return "", false
		}
		if strings.HasPrefix(user, "PLUGIN:") {
			slog.Default().Warn("CERTIFICATE_MAPFILE maps a SciToken to a plugin, which is not supported; refusing it",
				"name", authName, "mapping", user)
			return "", false
		}
		return user, true
	}
}

// certificateMapFileKey reads CERTIFICATE_MAPFILE and the options it is
// loaded with (Authentication::load_map_file). ok is false when it is unset.
func certificateMapFileKey(cfg *config.Config) (certMapKey, bool) {
	if cfg == nil {
		return certMapKey{}, false
	}
	path, _ := cfg.Get("CERTIFICATE_MAPFILE")
	path = strings.TrimSpace(path)
	if path == "" {
		return certMapKey{}, false
	}
	exclude, _ := cfg.Get("LOCAL_CONFIG_DIR_EXCLUDE_REGEXP")
	return certMapKey{
		path:      path,
		regexKeys: !cfg.GetBool("CERTIFICATE_MAPFILE_ASSUME_HASH_KEYS", false),
		exclude:   strings.TrimSpace(exclude),
	}, true
}

// loadCertificateMapFile returns the map file key names, reading it again
// after ReloadCertificateMapFile or when it has changed. It returns nil when
// the file cannot be read, as HTCondor then has no map file.
func loadCertificateMapFile(key certMapKey) *mapfile.MapFile {
	v, _ := certMapFiles.LoadOrStore(key, &certMapEntry{})
	e := v.(*certMapEntry)
	gen := certMapGeneration.Load()
	var stamp certMapStamp
	if fi, err := os.Stat(key.path); err == nil {
		stamp = certMapStamp{modTime: fi.ModTime(), size: fi.Size()}
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.loaded && e.gen == gen && e.stamp == stamp {
		return e.mf
	}
	e.mf = readCertificateMapFile(key)
	e.loaded, e.gen, e.stamp = true, gen, stamp
	return e.mf
}

// matchNothing excludes no file of an included directory.
var matchNothing = regexp.MustCompile(`[^\s\S]`)

func readCertificateMapFile(key certMapKey) *mapfile.MapFile {
	log := slog.Default()
	opts := mapfile.Options{RegexKeys: key.regexKeys, IncludeExclude: matchNothing}
	if key.exclude != "" {
		re, err := regexp.Compile(key.exclude)
		if err != nil {
			// HTCondor exits on an invalid LOCAL_CONFIG_DIR_EXCLUDE_REGEXP.
			log.Error("LOCAL_CONFIG_DIR_EXCLUDE_REGEXP is not a valid regular expression; not reading CERTIFICATE_MAPFILE",
				"file", key.path, "error", err)
			return nil
		}
		opts.IncludeExclude = re
	}
	mf, err := opts.Load(key.path)
	if err != nil {
		log.Error("reading CERTIFICATE_MAPFILE failed; no SciToken will be mapped", "file", key.path, "error", err)
		return nil
	}
	log.Debug("read CERTIFICATE_MAPFILE", "file", key.path, "lines", mf.Len(), "regex_keys", key.regexKeys)
	return mf
}

// sciTokensServerAudience reads SCITOKENS_SERVER_AUDIENCE, a list (empty
// unless set, as in condor_scitokens.cpp).
func sciTokensServerAudience(cfg *config.Config) []string {
	v, _ := cfg.Get("SCITOKENS_SERVER_AUDIENCE")
	return config.SplitConfigList(v)
}

// sciTokensForeignTokenIssuers is SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS when
// SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES is true and nil when it is false.
// HTCondor's defaults are true and https://aai-dev.egi.eu/auth/realms/egi.
func sciTokensForeignTokenIssuers(cfg *config.Config) []string {
	if !cfg.GetBool("SEC_SCITOKENS_ALLOW_FOREIGN_TOKEN_TYPES", true) {
		return nil
	}
	v, ok := cfg.Get("SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS")
	if !ok {
		v = defaultForeignTokenIssuers
	}
	return config.SplitConfigList(v)
}

// defaultForeignTokenIssuers is SEC_SCITOKENS_FOREIGN_TOKEN_ISSUERS's
// default in HTCondor's param table.
const defaultForeignTokenIssuers = "https://aai-dev.egi.eu/auth/realms/egi" //nolint:gosec // an issuer URL, not a credential

// defaultTCPSessionDeadline is SEC_TCP_SESSION_DEADLINE's default.
const defaultTCPSessionDeadline = 120 * time.Second

// TCPSessionDeadline returns SEC_TCP_SESSION_DEADLINE (seconds, default 120),
// the time DaemonCore gives a new command connection to finish the command
// protocol, as a cedar server.Server.HandshakeDeadline. A negative value
// means no deadline, and so does 0.
func TCPSessionDeadline(cfg *config.Config) time.Duration {
	if cfg == nil {
		return defaultTCPSessionDeadline
	}
	v, ok := cfg.Get("SEC_TCP_SESSION_DEADLINE")
	if !ok || strings.TrimSpace(v) == "" {
		return defaultTCPSessionDeadline
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		slog.Default().Error("config: SEC_TCP_SESSION_DEADLINE is not an integer", "value", v,
			"using", defaultTCPSessionDeadline.String())
		return defaultTCPSessionDeadline
	}
	if n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}
