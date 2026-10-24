package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/bbockelm/golang-htcondor/idmap"
	"github.com/bbockelm/golang-htcondor/logging"
)

// Demo mode runs a condor_placementd when the HTCondor it starts has one,
// so the placement pages -- the token page, the device flow, the admin
// Directory and access requests -- can be tried without a real pool.
//
// The two seeded IdP accounts keep exactly the sessions they have without
// it: "admin" and "user" are listed in a passwd file of the demo's own and
// mapped by login name, before the placementd is asked. Anyone else (the
// "newbie" account seeded only here) maps to no local account and falls
// through to the placementd, which does not map them either, so they get a
// placement-only session and can file an access request.

// demoPlacementProject is the project the demo map file grants.
const demoPlacementProject = "Demo"

// demoPlacementNewbie is the IdP account with no local account and no
// placementd mapping.
const demoPlacementNewbie = "newbie"

// demoPlacement is the demo pool's condor_placementd and the files it and
// htcondor-api read.
type demoPlacement struct {
	binary     string
	mapFile    string
	authzFile  string
	passwdFile string
}

// findDemoPlacementd returns the condor_placementd to run: the one in the
// SBIN directory of the HTCondor on PATH (beside condor_master, which is
// where the demo's SBIN points), else one on PATH. Empty when there is none.
func findDemoPlacementd() string {
	var candidates []string
	if master, err := exec.LookPath("condor_master"); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(master), "condor_placementd"))
	}
	if p, err := exec.LookPath("condor_placementd"); err == nil {
		candidates = append(candidates, p)
	}
	for _, c := range candidates {
		info, err := os.Stat(c)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return c
		}
	}
	return ""
}

// lookForDemoPlacementd returns the condor_placementd demo mode will run,
// or logs that there is none and returns "".
func lookForDemoPlacementd(logger *logging.Logger) string {
	bin := findDemoPlacementd()
	if bin == "" {
		logger.Info(logging.DestinationGeneral, "no condor_placementd found; placement features are off in demo mode")
		return ""
	}
	logger.Info(logging.DestinationGeneral, "Found condor_placementd; the demo pool will run it", "path", bin)
	return bin
}

// setUpDemoPlacement returns the demo's placementd, its files written into
// localDir, or nil when this HTCondor has none. Placement is optional in
// demo mode, so a placementd whose files cannot be written is left out
// rather than failing the demo.
func setUpDemoPlacement(localDir string, logger *logging.Logger) *demoPlacement {
	bin := lookForDemoPlacementd(logger)
	if bin == "" {
		return nil
	}
	p, err := newDemoPlacement(localDir, bin)
	if err != nil {
		logger.Warn(logging.DestinationGeneral, "Could not set up condor_placementd; placement features are off in demo mode",
			"error", err)
		return nil
	}
	return p
}

// newDemoPlacement writes the placementd's map files and the demo's passwd
// file into localDir.
func newDemoPlacement(localDir, binary string) (*demoPlacement, error) {
	p := &demoPlacement{
		binary:     binary,
		mapFile:    filepath.Join(localDir, "placementd_mapfile"),
		authzFile:  filepath.Join(localDir, "placementd_authorizations"),
		passwdFile: filepath.Join(localDir, "demo_passwd"),
	}
	files := map[string]string{
		// identity account authorizations expiry projects. An account
		// without a domain is in UID_DOMAIN, so these are the accounts
		// the two sessions already run as.
		p.mapFile: "# identity account authorizations expiry projects\n" +
			"admin admin READ,WRITE 0 " + demoPlacementProject + "\n" +
			"user user READ,WRITE 0 " + demoPlacementProject + "\n",
		// name|label|style|description
		p.authzFile: "READ|Read|normal|View jobs\n" +
			"WRITE|Write|warning|Submit and manage jobs\n",
		// The local accounts htcondor-api maps a sign-in to by name. Only
		// the name is read; no process runs as these.
		p.passwdFile: "admin:x:60001:60001:Demo administrator:/nonexistent:/sbin/nologin\n" +
			"user:x:60002:60002:Demo user:/nonexistent:/sbin/nologin\n",
	}
	for path, content := range files {
		//nolint:gosec // Read by the condor daemons, which may run as another user
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			return nil, fmt.Errorf("writing %s: %w", path, err)
		}
	}
	return p, nil
}

// daemonListEntry is what the placementd adds to DAEMON_LIST.
func (p *demoPlacement) daemonListEntry() string {
	if p == nil {
		return ""
	}
	return ", PLACEMENTD"
}

// condorConfig is the placementd's part of the demo pool's configuration.
func (p *demoPlacement) condorConfig() string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf(`
# condor_placementd, which issues placement tokens; htcondor-api fronts it.
PLACEMENTD = %s
PLACEMENTD_MAPFILE = %s
PLACEMENTD_AUTHORIZATIONS_MAPFILE = %s
PLACEMENTD_ADDRESS_FILE = $(LOG)/.placementd_address
PLACEMENTD_DEBUG = D_FULLDEBUG D_SECURITY

# A placement token carries no subject: the daemons look it up in
# TOKENS_DATABASE, where the placementd records it when it is issued.
SEC_USE_TOKENS_DATABASE = True
SEC_ACCEPT_CAPABILITY_TOKENS = True
`, p.binary, p.mapFile, p.authzFile)
}

// identityMap is the demo's HTTP_API_IDENTITY_MAP: the demo's own accounts
// by login name first, so admin and user sign in as themselves, then the
// placementd for everyone else.
func (p *demoPlacement) identityMap() (strategies []idmap.Strategy, passwdFile string) {
	if p == nil {
		return nil, ""
	}
	return []idmap.Strategy{idmap.StrategyUsername, idmap.StrategyPlacementd}, p.passwdFile
}

// printBanner tells the person running the demo where the placement pages
// are and which account shows what.
func (p *demoPlacement) printBanner(w io.Writer, baseURL string) {
	if p == nil {
		return
	}
	_, _ = fmt.Fprintf(w, "\n"+
		"========================================\n"+
		"Placement\n"+
		"========================================\n"+
		"condor_placementd: %s\n"+
		"Placement token:   %s/placement (sign in as user or admin)\n"+
		"Device flow:       %s/auth/device_authorization\n"+
		"Directory:         %s/admin/placement (sign in as admin)\n"+
		"Access requests:   sign in as %s to request access, then approve it\n"+
		"                   on the Requests tab of %s/admin/placement\n"+
		"========================================\n\n",
		p.binary, baseURL, baseURL, baseURL, demoPlacementNewbie, baseURL)
}

// waitForAddressFile waits, up to timeout, for the placementd to write its
// address file, so the placement pages work from the first sign-in. Not
// fatal: htcondor-api finds a placementd that starts later on its own.
func (p *demoPlacement) waitForAddressFile(localDir string, timeout time.Duration, logger *logging.Logger) {
	if p == nil {
		return
	}
	path := filepath.Join(localDir, "log", ".placementd_address")
	deadline := time.Now().Add(timeout)
	for {
		if addr, err := readAddressFile(path); err == nil && addr != "" {
			logger.Info(logging.DestinationGeneral, "condor_placementd is ready", "address", addr)
			return
		}
		if time.Now().After(deadline) {
			logger.Warn(logging.DestinationGeneral,
				"condor_placementd has not started yet; the placement pages appear once it does",
				"waited", timeout, "log", filepath.Join(localDir, "log", "PlacementdLog"))
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}
