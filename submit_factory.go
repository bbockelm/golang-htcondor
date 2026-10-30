package htcondor

// Late materialization: the job factory a submit file asks for with
// max_materialize, max_idle or materialize_max_idle.
//
// A factory submission does not send proc ads at all. It sends the cluster
// ad, the itemdata rows, and a *submit digest* -- the submit file reduced to
// what the schedd needs to build each proc itself -- and the schedd
// materializes jobs from it on demand, keeping at most max_idle of them idle.
// A submission of a million jobs is then a handful of round trips and one
// cluster ad in the queue rather than a million proc ads.
//
// Everything here is the client half, and all of it is decided before the
// schedd is involved: whether the file wants a factory, the materialize
// limit, the itemdata rows and the digest text. The one thing that is not is
// the path the schedd spools the itemdata to, which comes back from
// SendMaterializeData and names the file the digest's queue statement reads;
// that is why Digest takes it as an argument.
//
// The digest format is not documented anywhere but
// SubmitHash::make_digest/append_queue_statement, and the schedd parses it
// with the same submit-file parser it would use on the file itself, so the
// text has to be right down to the byte. fuzz/submit compares what this
// builds against the C++ that defines it.

import (
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"
)

// unitSeparator is the ASCII US byte that separates the fields of one
// itemdata row on the wire.
const unitSeparator = "\x1f"

// factoryRequirementsLine tells the schedd not to rebuild Requirements per
// proc but to take the cluster ad's.
//
// It has to: the digest is pruned, so the keywords SetRequirements would read
// are not all in it, and a Requirements rebuilt from what is left would
// constrain the job differently from the one the submitter saw. The user's
// own `requirements` command is left out of the digest for the same reason.
const factoryRequirementsLine = "FACTORY.Requirements=MY.Requirements\n"

// perProcKnobs are the macro names whose values change from proc to proc, so
// a digest must keep references to them unexpanded and let the schedd fill
// them in. A queue statement's loop variables join them.
var perProcKnobs = []string{"Process", "ProcId", "Step", "Row", "Node", "Item", "TaskId"}

// digestOmittedKeys never appear in a digest whatever their value.
//
// getenv (and its alternate spelling) reads the submitting host's
// environment, which the schedd is not; its effect is already in the cluster
// ad's Env. requirements is replaced by factoryRequirementsLine. The
// on_evict_checks family is left out because expanding the tag list and the
// transform bodies in step is not something make_digest does -- a per-proc
// on_evict_checks is simply not supported.
var digestOmittedKeys = map[string]struct{}{
	"getenv":           {},
	"get_env":          {},
	"requirements":     {},
	"on_evict_checks":  {},
	"transformonevict": {},
}

// transformBodyPrefixes are the two spellings of the per-tag transform bodies
// that on_evict_checks names; they are omitted alongside it.
var transformBodyPrefixes = []string{"transform_body_", "transformbody_"}

// JobFactory is what a late-materialization submission sends to the schedd in
// place of per-proc job ads.
//
// The zero value is not useful; get one from SubmitFile.Factory.
type JobFactory struct {
	// ClusterID is the cluster the digest was built for. $(ClusterId) is
	// expanded in the digest, so a digest is only valid for this cluster.
	ClusterID int

	// MaxMaterialize is the limit to send with the digest: how many procs
	// the schedd may have materialized at once. It is already clamped to
	// the job count and to at least one, as condor_submit clamps it.
	MaxMaterialize int

	// TotalProcs is how many jobs the queue statement asks for.
	TotalProcs int

	// Vars are the queue statement's loop variables, in order.
	Vars []string

	// Items are the itemdata rows exactly as they go on the wire: a row
	// with more than one field has its fields joined with the ASCII unit
	// separator, and every row ends in a newline. Empty when the queue
	// statement iterates a count rather than a list.
	Items []string

	// body is the digest without its queue statement, which Digest appends
	// once the schedd has named the file it spooled Items to.
	body string

	// queueCount is the queue statement's repeat count and slice is its
	// slice expression, both needed to write that queue statement.
	queueCount int
	slice      string
}

// Digest returns the submit digest to send with SetJobFactory.
//
// itemsFilename is the path SendMaterializeData reported for the spooled
// itemdata; the queue statement at the end of the digest reads the rows back
// from it. Pass "" when there are no items, in which case the queue statement
// is a plain count.
func (f *JobFactory) Digest(itemsFilename string) string {
	var b strings.Builder
	b.WriteString(f.body)

	// append_queue_statement: a blank line, then the queue statement the
	// schedd iterates. The count is written only when the statement had
	// one, and the loop variables only when it named any.
	b.WriteString("\nQueue ")
	if f.queueCount != 0 {
		b.WriteString(strconv.Itoa(f.queueCount))
		b.WriteString(" ")
	}
	if len(f.Vars) > 0 {
		b.WriteString(strings.Join(f.Vars, ","))
		b.WriteString(" ")
	}
	if itemsFilename != "" {
		b.WriteString("from ")
		if f.slice != "" {
			b.WriteString(f.slice)
			b.WriteString(" ")
		}
		b.WriteString(itemsFilename)
	}
	b.WriteString("\n")
	return b.String()
}

// WantFactory reports whether the submit file asks to be submitted as a job
// factory, and the materialize limit it asks for before clamping.
//
// This is want_factory_submit: max_materialize sets the limit outright, and
// max_idle (or materialize_max_idle) asks for a factory with no limit of its
// own. An unparsable value is an error rather than a silent no, because
// condor_submit fails the submission on one.
func (sf *SubmitFile) WantFactory() (limit int64, want bool, err error) {
	if v, ok := sf.submitCommandAlt("max_materialize", "JobMaterializeLimit"); ok {
		n, err := submitValueAsLong("max_materialize", v)
		if err != nil {
			return 0, false, err
		}
		return n, true, nil
	}
	for _, key := range []string{"max_idle", "materialize_max_idle"} {
		v, ok := sf.submitCommandAlt(key, "JobMaterializeMaxIdle")
		if !ok {
			continue
		}
		if _, err := submitValueAsLong(key, v); err != nil {
			return 0, false, err
		}
		// No limit was named, so every proc may be materialized at once;
		// the clamp in Factory brings it down to the job count.
		return 0, true, nil
	}
	return 0, false, nil
}

// submitValueAsLong is string_is_long_param: a decimal literal, or failing
// that a ClassAd expression that evaluates to an integer. The range check is
// condor_submit's, which rejects anything that does not fit in an int.
func submitValueAsLong(key, value string) (int64, error) {
	trimmed := strings.TrimRight(value, " \t\n\v\f\r")
	n, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		expr, parseErr := classad.ParseExpr(value)
		if parseErr != nil {
			return 0, fmt.Errorf("%s=%s is invalid, must eval to an integer", key, value)
		}
		ad := classad.New()
		_ = ad.Set("CondorLong", expr)
		v, ok := ad.EvaluateAttrInt("CondorLong")
		if !ok {
			return 0, fmt.Errorf("%s=%s is invalid, must eval to an integer", key, value)
		}
		n = v
	}
	if n < math.MinInt32 || n >= math.MaxInt32 {
		return 0, fmt.Errorf("%s=%s is invalid, must eval to an integer", key, value)
	}
	return n, nil
}

// Factory builds the job factory this submit file asks for, for the given
// cluster. It returns nil when the file does not ask for one.
//
// The caller sends Items with SendMaterializeData first and then
// Digest(<the filename it returned>) with SetJobFactory, which is the order
// condor_submit uses, because the digest's queue statement names that file.
func (sf *SubmitFile) Factory(clusterID int) (*JobFactory, error) {
	limit, want, err := sf.WantFactory()
	if err != nil {
		return nil, err
	}
	if !want {
		return nil, nil
	}

	f := &JobFactory{
		ClusterID:  clusterID,
		TotalProcs: sf.queueCount,
		Vars:       append([]string(nil), sf.queueVars...),
		queueCount: sf.queueRepeat(),
		slice:      sf.queueSlice(),
	}

	f.Items, err = sf.itemdataRows()
	if err != nil {
		return nil, err
	}

	// condor_submit's clamp: no limit means every job, and never below one.
	materialize := limit
	if materialize <= 0 {
		materialize = math.MaxInt32
	}
	if int64(f.TotalProcs) < materialize {
		materialize = int64(f.TotalProcs)
	}
	if materialize < 1 {
		materialize = 1
	}
	f.MaxMaterialize = int(materialize)

	// The digest is built before any loop variable is live. A digest built
	// after would hold the first row's values in place of the references,
	// and every job the factory made would be a copy of the first.
	f.body, err = sf.makeDigest(clusterID, f.Vars, len(f.Items) == 0)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// itemdataRows encodes the queue statement's items the way
// SendMaterializeData sends them: a row holding more than one field is split
// into as many fields as there are loop variables and rejoined with the ASCII
// unit separator, a row that already holds one is passed through, and every
// row is newline-terminated.
func (sf *SubmitFile) itemdataRows() ([]string, error) {
	items := sf.queueItems()
	if len(items) == 0 {
		return nil, nil
	}
	rows := make([]string, 0, len(items))
	for _, item := range items {
		row := item
		if len(sf.queueVars) > 1 && !strings.Contains(item, unitSeparator) {
			fields := splitQueueItem(item, len(sf.queueVars))
			if len(fields) == 0 {
				return nil, fmt.Errorf("itemdata row %q has no fields", item)
			}
			row = strings.Join(fields, unitSeparator)
		}
		if !strings.HasSuffix(row, "\n") {
			row += "\n"
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// makeDigest is SubmitHash::make_digest: the submit file's macros, with every
// expansion that does not depend on a per-proc knob already performed, and
// every key whose effect the cluster ad already carries dropped.
//
// noItems says the queue statement iterates a count rather than a list. That
// matters because condor_submit reads the first row before building the
// digest, and reading from an empty list defines the macro Item as empty --
// which lands in the digest, since Item is not a prunable keyword.
func (sf *SubmitFile) makeDigest(clusterID int, vars []string, noItems bool) (string, error) {
	var b strings.Builder

	// A container or docker job with no universe command of its own has its
	// topping written out, so the schedd does not have to work it out again.
	if _, ok := sf.submitCommandAlt("universe", "JobUniverse"); !ok {
		if topping := sf.impliedTopping(); topping != "" {
			b.WriteString("Universe=" + topping + "\n")
		}
	}

	b.WriteString(factoryRequirementsLine)

	// $(ClusterId) is the same for every proc, so the digest carries its
	// value rather than the reference. The schedd never sees the name, so
	// it has to resolve here; these are the live macros condor_submit has
	// set by this point.
	if clusterID > 0 {
		sf.cfg.Set("Cluster", strconv.Itoa(clusterID))
		sf.cfg.Set("ClusterId", strconv.Itoa(clusterID))
	}

	// $(ItemIndex) expands to 0 and stays that way for every job the
	// factory makes.
	//
	// That is not an oversight here, it is HTCondor's behavior. ItemIndex
	// and Row are two names for one macro in the submit hash, but only Row
	// is in the set a digest protects, so ItemIndex is expanded while the
	// digest is built -- and nothing has set a row live by then, so it
	// takes the default, which is 0. A submit file that numbers its output
	// with $(ItemIndex) therefore gets o.0 for every proc under late
	// materialization and the row number without it. Matching it is not an
	// endorsement; a digest that differed would be a worse bug than the one
	// it worked around.
	if _, assigned := sf.submitCommand("ItemIndex"); !assigned {
		sf.cfg.Set("ItemIndex", "0")
	}

	skip := skipKnobSet(vars, clusterID)
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %w", err)
	}

	for _, key := range sf.digestKeys(noItems) {
		if digestOmits(key) {
			continue
		}
		if strings.HasPrefix(key, "$") {
			continue // a meta parameter, not a submit command
		}
		raw, _ := sf.cfg.RawValue(key)
		rhs, pending, err := sf.cfg.SelectiveExpand(raw, func(name string) bool {
			_, protected := skip[strings.ToLower(name)]
			return protected
		})
		if err != nil {
			return "", fmt.Errorf("failed to expand %s for the submit digest: %w", key, err)
		}
		hasPending := pending > 0
		rhs = digestFixup(key, rhs, hasPending, cwd)
		if !hasPending && keyIsPrunable(key) {
			continue
		}
		writeDigestEntry(&b, key, rhs)
	}

	return b.String(), nil
}

// writeDigestEntry writes one key=value line, or the @=end block form when
// the value spans lines, which is how the schedd's parser reads it back.
func writeDigestEntry(b *strings.Builder, key, rhs string) {
	b.WriteString(key)
	if strings.Contains(rhs, "\n") {
		b.WriteString("@=end\n")
		b.WriteString(rhs)
		if !strings.HasSuffix(rhs, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("@end")
	} else {
		b.WriteString("=")
		b.WriteString(rhs)
	}
	b.WriteString("\n")
}

// digestKeys returns the macro names a digest iterates, in the order
// HTCondor's macro table holds them.
//
// The submit file's own assignments are sorted case-insensitively, because
// the hash is sorted once the file has been read. Item comes after them
// rather than among them: condor_submit defines it when it reads the first
// row, which is after that sort, and an unsorted tail is where the macro
// table puts anything defined later.
func (sf *SubmitFile) digestKeys(noItems bool) []string {
	keys := make([]string, 0, len(sf.assigned)+1)
	var hasItem bool
	for upper, spelling := range sf.assigned {
		if upper == "ITEM" {
			hasItem = true
		}
		keys = append(keys, spelling)
	}
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(keys[i]) < strings.ToLower(keys[j])
	})
	if noItems && !hasItem {
		keys = append(keys, "Item")
	}
	return keys
}

// skipKnobSet is per_proc_keys: the macro names whose expansion a digest
// leaves to the schedd, lowercased for case-insensitive matching.
//
// $(ClusterId) is not among them when the cluster is known, because it is the
// same for every proc and expanding it now saves the schedd the work. It is
// among them when it is not, because then nobody can expand it yet.
func skipKnobSet(vars []string, clusterID int) map[string]struct{} {
	skip := make(map[string]struct{}, len(perProcKnobs)+len(vars)+2)
	for _, k := range perProcKnobs {
		skip[strings.ToLower(k)] = struct{}{}
	}
	for _, v := range vars {
		skip[strings.ToLower(v)] = struct{}{}
	}
	if clusterID <= 0 {
		skip["cluster"] = struct{}{}
		skip["clusterid"] = struct{}{}
	}
	return skip
}

// digestOmits reports whether a key never belongs in a digest.
func digestOmits(key string) bool {
	lower := strings.ToLower(key)
	if _, omit := digestOmittedKeys[lower]; omit {
		return true
	}
	for _, prefix := range transformBodyPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// keyIsPrunable reports whether a key may be dropped from a digest when its
// value has no expansion left pending.
//
// Any my. key is prunable: a custom attribute is copied to the cluster ad
// verbatim and every proc chains to it.
func keyIsPrunable(key string) bool {
	lower := strings.ToLower(key)
	if strings.HasPrefix(lower, "my.") {
		return true
	}
	_, prunable := digestPrunableKeywords[lower]
	return prunable
}

// digestFixupKeys maps the keys fixup_rhs_for_digest rewrites to what it does
// to them. The two path keys are resolved against the submitting directory,
// not the job's Iwd -- an initialdir the schedd read relative to its own
// working directory would be a different directory entirely.
var digestFixupKeys = map[string]bool{
	"initial_dir": true,
	"initialdir":  true,
	"iwd":         true,
	"job_iwd":     true,
}

// digestFixup applies fixup_rhs_for_digest.
//
// The executable keys (executable, Cmd) are in HTCondor's table too but
// nothing here acts on them: the fixup applies only when the value has no
// pending expansion, and executable is prunable, so a value with no pending
// expansion has already been dropped.
func digestFixup(key, rhs string, hasPending bool, cwd string) string {
	if hasPending || rhs == "" {
		return rhs
	}
	if !digestFixupKeys[strings.ToLower(key)] {
		return rhs
	}
	if strings.Contains(rhs, "$$(") || isURL(rhs) {
		return rhs
	}
	return fullPath(rhs, cwd)
}

// queueItems returns the queue statement's rows as the iterator read them,
// before any split into loop variables. Nil when the statement iterates a
// count rather than a list.
func (sf *SubmitFile) queueItems() []string {
	if src, ok := sf.queueIterator.(rawItemSource); ok {
		return src.rawItems()
	}
	return nil
}

// queueRepeat is the queue statement's repeat count: how many jobs per row.
func (sf *SubmitFile) queueRepeat() int {
	if sf.queueStmt == nil || sf.queueStmt.Count <= 0 {
		return 1
	}
	return sf.queueStmt.Count
}

// queueSlice is the queue statement's slice expression, which selects a
// subset of the rows. The Go grammar does not accept one today, so this is
// always empty; it is read here rather than assumed so that a grammar that
// learns to accept one writes it into the digest instead of silently
// submitting every row.
func (sf *SubmitFile) queueSlice() string {
	if sf.queueStmt == nil {
		return ""
	}
	return sf.queueStmt.Slice
}

// impliedTopping is the vanilla-universe topping a submit file that names no
// universe still asks for by naming a container or docker image. make_digest
// writes it out so the schedd does not have to infer it again.
func (sf *SubmitFile) impliedTopping() string {
	for _, key := range []string{"container_image", "ContainerImage", "docker_image", "DockerImage"} {
		if _, ok := sf.submitCommand(key); ok {
			return "container"
		}
	}
	return ""
}

// splitQueueItem splits one itemdata row into the fields of numCols loop
// variables, the way SubmitForeachArgs::split_item does.
func splitQueueItem(item string, numCols int) []string {
	return splitItemColumns(item, numCols)
}

// DigestKeywordIsPrunable reports whether a name is one of the submit
// keywords or job attributes a submit digest may drop.
//
// Exported for the differential harness in fuzz/submit, which compares this
// table against the one HTCondor's own libcondor_utils exposes.
func DigestKeywordIsPrunable(name string) bool {
	_, ok := digestPrunableKeywords[strings.ToLower(name)]
	return ok
}

// DigestPrunableKeywordNames returns every name in that table, lowercased and
// in no particular order. See DigestKeywordIsPrunable.
func DigestPrunableKeywordNames() []string {
	names := make([]string, 0, len(digestPrunableKeywords))
	for name := range digestPrunableKeywords {
		names = append(names, name)
	}
	return names
}
