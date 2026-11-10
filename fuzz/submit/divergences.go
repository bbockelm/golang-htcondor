package fuzzsubmit

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// The recorded divergences are one file per attribute under divergences/,
// rather than four map literals in this file.
//
// They used to be the literals, and every pull request in this campaign
// conflicted with every other one on them: two fixes landing in the same week
// each delete a line, git sees adjacent edits to one hunk, and the rebase is
// manual every time -- on the one file whose merge rule is easy to get wrong
// (an entry either side deleted is a FIX, so the resolution is the
// intersection). One file per entry makes that rule structural: a fix deletes
// its own file and a finding adds one, so two of them never touch the same
// bytes.
//
// The layout, which loadDivergences parses:
//
//	divergences/seed/<attr>.md               knownDivergent
//	divergences/generated/<attr>.md          knownDivergentGenerated
//	divergences/host/<attr>.md               hostDerived
//	divergences/universe/<universe>/<attr>.md  knownDivergentInUniverse
//
// The file's name is the attribute, lower-cased, and its contents are the
// reason -- the same text the map held. See divergences/README.md.
//
//go:embed divergences
var divergenceFiles embed.FS

// hostDerived are attributes whose value comes from the clock, the machine or
// the account running the parse rather than from the submit file. The two sides
// cannot agree on them by construction -- the C++ oracle is pinned to a fixed
// submit time and user, and the Go parser reads the real clock -- so they are
// never compared. This list must stay SHORT and justified: every name here is a
// hole in the oracle.
var hostDerived map[string]string

// knownDivergent are attributes the two parsers genuinely disagree about today.
// Each entry is a finding, not an excuse: the reason says what the difference
// is, so the list reads as the inventory of Go/C++ submit drift. Removing an
// entry is how a fix gets locked in -- see TestRecordedDivergencesStillDiverge,
// which fails when one of these starts agreeing.
var knownDivergent map[string]string

// knownDivergentGenerated are the divergences the GENERATED corpus found, which
// the hand-written seeds never reached. They are kept apart from knownDivergent
// only to record which sweep found them -- the seeds and the generated files
// are compared the same way, and record() consults both.
var knownDivergentGenerated map[string]string

// knownDivergentInUniverse excuses an attribute only inside one job universe.
//
// It exists so a quirk of a single universe cannot excuse that attribute
// everywhere. Putting "cmd" in knownDivergent would have undone the Cmd/UserLog
// path comparison, which is the whole point of having it compared.
var knownDivergentInUniverse map[int]map[string]string

// sweepExempt holds, per attribute, why the sweep in
// TestRecordedDivergencesStillDiverge cannot prove that entry still
// reproduces -- written as a last line in the entry's file:
//
//	Sweep cannot prove this: <why>
//
// The sweep decides an entry is stale by an ABSENCE: the attribute was
// compared and never diverged. That reasoning does not hold for every entry.
// Some are about something the merged-ad comparison cannot see at all, like
// WHERE an attribute is written; others need a submit file the generator does
// not produce. Without this marker those entries read as fixed, and deleting
// them would drop a real finding -- so the marker makes the limit explicit
// and names what checks the entry instead.
//
// only under the libcondor_utils tag.
//
//nolint:unused // read by TestRecordedDivergencesStillDiverge, which builds
var sweepExempt map[string]string

// entryTrait holds, per attribute, the one upstream change its entry is about
// and which side of that change it belongs to -- written as a last line in the
// entry's file:
//
//	Oracle: has <ticket>
//	Oracle: lacks <ticket>
//
// An entry without one applies to every oracle, which is right for a
// divergence that is ours rather than a difference between two HTCondors.
// activateDivergences drops the entries whose trait does not match the linked
// oracle, before any test consults them.
//
// only under the libcondor_utils tag.
//
//nolint:unused // read by activateDivergences, which runs from TestMain
var entryTrait map[string]traitReq

// traitReq is one entry's requirement: the ticket naming an upstream change,
// and whether the entry applies when the oracle HAS it.
type traitReq struct {
	ticket string
	has    bool
}

// divergenceLoadErr is why the entries above are empty, if they are.
// TestDivergenceEntriesLoad reports it; nothing else can, because a test
// helper package cannot refuse to build.
//
// libcondor_utils tag.
//
//nolint:unused // read by that test, which builds only under the
var divergenceLoadErr error

// universeByName maps the directory name under divergences/universe/ to its
// JobUniverse number. A name that is not here is an error rather than a
// silently ignored directory, so a typo cannot quietly stop excusing an
// attribute -- or quietly start.
var universeByName = map[string]int{
	"java": universeJava,
}

func init() {
	divergenceLoadErr = loadDivergences()
}

// loadDivergences fills the four collections from the embedded files.
func loadDivergences() error {
	hostDerived = map[string]string{}
	sweepExempt = map[string]string{}
	entryTrait = map[string]traitReq{}
	knownDivergent = map[string]string{}
	knownDivergentGenerated = map[string]string{}
	knownDivergentInUniverse = map[int]map[string]string{}

	byKind := map[string]map[string]string{
		"seed":      knownDivergent,
		"generated": knownDivergentGenerated,
		"host":      hostDerived,
	}

	return fs.WalkDir(divergenceFiles, "divergences", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := strings.TrimPrefix(p, "divergences/")
		if rel == "README.md" {
			return nil
		}
		if !strings.HasSuffix(rel, ".md") {
			return fmt.Errorf("divergences/%s: every entry is a .md file", rel)
		}
		reason, exempt, trait, err := readDivergence(p)
		if err != nil {
			return err
		}

		// gen.go declares a package-level `path`, so this file cannot import
		// the path package; the entry's name is the last element either way.
		parts := strings.Split(rel, "/")
		attr := strings.TrimSuffix(parts[len(parts)-1], ".md")
		if exempt != "" {
			sweepExempt[attr] = exempt
		}
		if trait != nil {
			entryTrait[attr] = *trait
		}
		switch {
		case len(parts) == 2 && byKind[parts[0]] != nil:
			byKind[parts[0]][attr] = reason
		case len(parts) == 3 && parts[0] == "universe":
			universe, ok := universeByName[parts[1]]
			if !ok {
				return fmt.Errorf("divergences/%s: %q is not a universe name in universeByName", rel, parts[1])
			}
			if knownDivergentInUniverse[universe] == nil {
				knownDivergentInUniverse[universe] = map[string]string{}
			}
			knownDivergentInUniverse[universe][attr] = reason
		default:
			return fmt.Errorf("divergences/%s: expected seed/, generated/, host/ or universe/<universe>/", rel)
		}
		if attr != strings.ToLower(attr) {
			return fmt.Errorf("divergences/%s: an attribute's file name is lower-cased, because record() folds the name it looks up", rel)
		}
		return nil
	})
}

// sweepExemptPrefix and oracleTraitPrefix introduce the optional last lines of
// an entry's file; see sweepExempt and entryTrait.
const (
	sweepExemptPrefix = "Sweep cannot prove this:"
	oracleTraitPrefix = "Oracle:"
)

// readDivergence reads one entry: the file's contents are the reason, and the
// optional marker lines at the end are returned separately rather than as part
// of it. Either marker may come last, so they are peeled off in a loop.
func readDivergence(p string) (reason, exempt string, trait *traitReq, err error) {
	b, err := divergenceFiles.ReadFile(p)
	if err != nil {
		return "", "", nil, err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for len(lines) > 0 {
		last := lines[len(lines)-1]
		switch {
		case strings.HasPrefix(last, sweepExemptPrefix):
			if exempt != "" {
				return "", "", nil, fmt.Errorf("%s: two %q lines", p, sweepExemptPrefix)
			}
			exempt = strings.TrimSpace(strings.TrimPrefix(last, sweepExemptPrefix))
			if exempt == "" {
				return "", "", nil, fmt.Errorf("%s: %q needs a reason after it", p, sweepExemptPrefix)
			}
		case strings.HasPrefix(last, oracleTraitPrefix):
			if trait != nil {
				return "", "", nil, fmt.Errorf("%s: an entry is about at most one upstream change", p)
			}
			req, terr := parseTraitReq(strings.TrimPrefix(last, oracleTraitPrefix))
			if terr != nil {
				return "", "", nil, fmt.Errorf("%s: %w", p, terr)
			}
			trait = req
		default:
			// Not a marker, so the reason ends here.
			return finishReason(p, lines, exempt, trait)
		}
		lines = lines[:len(lines)-1]
	}
	return finishReason(p, lines, exempt, trait)
}

// finishReason joins what is left of an entry's file after its marker lines
// were peeled off, and refuses an entry that is nothing but markers.
func finishReason(p string, lines []string, exempt string, trait *traitReq) (string, string, *traitReq, error) {
	reason := strings.TrimRight(strings.Join(lines, "\n"), "\n")
	if strings.TrimSpace(reason) == "" {
		return "", "", nil, fmt.Errorf("%s: an entry's file is its reason, and this one is empty", p)
	}
	return reason, exempt, trait, nil
}

// parseTraitReq reads "has <ticket>" or "lacks <ticket>". The ticket has to be
// one oracleTraits probes for, so a typo cannot quietly park an entry on a
// trait nothing decides.
func parseTraitReq(s string) (*traitReq, error) {
	fields := strings.Fields(s)
	if len(fields) != 2 {
		return nil, fmt.Errorf("%q takes `has <ticket>` or `lacks <ticket>`, got %q", oracleTraitPrefix, strings.TrimSpace(s))
	}
	req := traitReq{ticket: fields[1]}
	switch fields[0] {
	case "has":
		req.has = true
	case "lacks":
		req.has = false
	default:
		return nil, fmt.Errorf("%q takes `has` or `lacks`, got %q", oracleTraitPrefix, fields[0])
	}
	for _, tr := range oracleTraits {
		if tr.ticket == req.ticket {
			return &req, nil
		}
	}
	return nil, fmt.Errorf("%q is not a ticket oracleTraits probes for", req.ticket)
}

// activateDivergences drops the entries that do not apply to the linked
// oracle, and returns their attribute names for the run's log.
//
// Dropping is what keeps the two oracles honest in both directions. An entry
// recording upstream drift must not excuse anything against the pinned oracle,
// which does not have the change; once the Go side is fixed ahead of a release
// the same entry flips to `lacks`, and must not excuse anything against the
// oracle that does. Either way the entry that does not apply is gone before a
// comparison runs, so TestRecordedDivergencesStillDiverge never sweeps it
// either.
//
//nolint:unused // called by TestMain, which builds only under the tag
func activateDivergences(have map[string]bool) []string {
	var dropped []string
	for attr, req := range entryTrait {
		if have[req.ticket] == req.has {
			continue
		}
		delete(knownDivergent, attr)
		delete(knownDivergentGenerated, attr)
		delete(hostDerived, attr)
		delete(sweepExempt, attr)
		for _, byAttr := range knownDivergentInUniverse {
			delete(byAttr, attr)
		}
		dropped = append(dropped, attr)
	}
	sort.Strings(dropped)
	return dropped
}
