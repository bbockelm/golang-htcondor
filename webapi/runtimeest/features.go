package runtimeest

import (
	"math"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/classad"

	"github.com/bbockelm/golang-htcondor/webapi/internal/jobargs"
)

// Level is how a job is grouped with others for an estimate, from the
// most specific (its own cluster) to the least (all of its owner's jobs).
// Every level is confined to one owner and to one kind of job (see
// Features.Kind): an estimate is never built from another user's jobs.
type Level int

// The levels, most specific first. The order is the tie-break: when two
// levels have done about as well, the more specific one answers.
const (
	// LevelCluster is the job's completed siblings in the same cluster.
	LevelCluster Level = iota
	// LevelExact is jobs running the same program with the same
	// arguments, up to directories and hashes.
	LevelExact
	// LevelTemplate is LevelExact with every number masked, so
	// "--seed 4" and "--seed 9" group together.
	LevelTemplate
	// LevelBatch is jobs with the same JobBatchName, less any trailing
	// run number or hash.
	LevelBatch
	// LevelIwd is jobs submitted from the same working directory, with
	// digit runs masked.
	LevelIwd
	// LevelCmd is jobs running the same program, whatever the arguments.
	LevelCmd
	// LevelOwner is all of the owner's jobs of the same kind.
	LevelOwner

	numLevels
)

var levelNames = [numLevels]string{"cluster", "exact", "template", "batch", "iwd", "cmd", "owner"}

// String is the level's name as it appears in the API and in metrics.
func (l Level) String() string {
	if l < 0 || l >= numLevels {
		return "unknown"
	}
	return levelNames[l]
}

// rough reports whether an estimate from l is only a rough guess (see
// Result.Rough): LevelCmd and LevelOwner.
func (l Level) rough() bool {
	return l >= LevelCmd
}

// Levels lists every level, most specific first.
func Levels() []Level {
	out := make([]Level, numLevels)
	for i := range out {
		out[i] = Level(i)
	}
	return out
}

// Features is what a job's runtime is predicted from.
type Features struct {
	Owner     string
	ClusterID int64
	Cmd       string
	// Args is the job's argv, already split (see jobargs).
	Args      []string
	Iwd       string
	BatchName string
	// Universe is the job's JobUniverse; 0 (not known) is taken as
	// vanilla.
	Universe int64
	// DAGNode is whether the job is a node of a DAG (DAGManJobId is set).
	DAGNode bool
	// Container is whether the job runs in a container (see
	// isContainerJob). Which image does not matter.
	Container bool
}

// Universes the estimator treats specially.
const (
	UniverseVanilla   = 5
	UniverseScheduler = 7
	UniverseLocal     = 12
)

// Estimated reports whether jobs like f get an estimate at all.
// Scheduler- and local-universe jobs -- DAGMan, mostly -- run as long as
// the work they manage, so their own history says nothing useful.
func (f *Features) Estimated() bool {
	return f.Universe != UniverseScheduler && f.Universe != UniverseLocal
}

// Kind is the kind of job f is, which every group is confined to: its
// universe, whether it is a DAG node and whether it runs in a container
// -- "u5", "u5|dag", "u5|ctr" or "u5|dag|ctr". A DAG node and a
// standalone job of the same owner never share a group, even running the
// same command, nor do a container job and a bare one, nor jobs of
// different universes.
//
// The container flag is not the image: an owner who moves a command to
// a new image keeps its history, which a key on the image would throw
// away. The same script run in a container and bare can take very
// different times: 2.4x apart, by median, on a replayed access point.
func (f *Features) Kind() string {
	u := f.Universe
	if u <= 0 {
		u = UniverseVanilla
	}
	k := "u" + strconv.FormatInt(u, 10)
	if f.DAGNode {
		k += "|dag"
	}
	if f.Container {
		k += "|ctr"
	}
	return k
}

// containerFlagAttrs and containerImageAttrs mark a container job (see
// isContainerJob).
var (
	containerFlagAttrs  = []string{"WantContainer", "WantDocker"}
	containerImageAttrs = []string{"ContainerImage", "DockerImage", "SingularityImage"}
)

// FeatureAttrs are the job attributes FeaturesFromAd reads.
var FeatureAttrs = slices.Concat(
	[]string{"Owner", "ClusterId", "ProcId", "Cmd", "Arguments", "Args", "Iwd", "JobBatchName", "JobUniverse", "DAGManJobId"},
	containerFlagAttrs, containerImageAttrs)

// isContainerJob reports whether a job runs in a container. condor_submit
// marks one with WantContainer (container universe, or any vanilla job
// with a container_image or docker_image) or WantDocker (docker
// universe) and records the image in ContainerImage or DockerImage;
// SingularityImage is the older convention, set by the submitter
// (+SingularityImage) and read by the execute node's
// SINGULARITY_IMAGE_EXPR. Any one of them is enough: history records
// written by an older schedd, or projected without the flags, may
// carry only the image.
func isContainerJob(ad *classad.ClassAd) bool {
	for _, a := range containerFlagAttrs {
		if b, ok := ad.EvaluateAttrBool(a); ok && b {
			return true
		}
	}
	for _, a := range containerImageAttrs {
		if s, ok := ad.EvaluateAttrString(a); ok && strings.TrimSpace(s) != "" {
			return true
		}
	}
	return false
}

// FeaturesFromAd reads a job's features from its ad, live or historical.
func FeaturesFromAd(ad *classad.ClassAd) Features {
	var f Features
	f.Owner, _ = ad.EvaluateAttrString("Owner")
	f.ClusterID, _ = intAttr(ad, "ClusterId")
	f.Cmd, _ = ad.EvaluateAttrString("Cmd")
	f.Args = jobargs.FromAd(ad)
	f.Iwd, _ = ad.EvaluateAttrString("Iwd")
	f.BatchName, _ = ad.EvaluateAttrString("JobBatchName")
	f.Universe, _ = intAttr(ad, "JobUniverse")
	_, f.DAGNode = intAttr(ad, "DAGManJobId")
	f.Container = isContainerJob(ad)
	return f
}

// Keys are the group a job falls into at each level. An empty key means
// the level does not apply to the job -- it has no batch name, say --
// and must not group it with every other job that has none either.
type Keys struct {
	owner string
	kind  string
	k     [numLevels]string
}

// Owner is the owner the keys are confined to.
func (k Keys) Owner() string { return k.owner }

// Kind is the kind of job the keys are confined to (see Features.Kind).
func (k Keys) Kind() string { return k.kind }

// Key is the job's group at one level, or "" when the level does not
// apply.
func (k Keys) Key(l Level) string {
	if l < 0 || l >= numLevels {
		return ""
	}
	return k.k[l]
}

// keySep joins an owner to the rest of a key. A control character, so
// no owner name or path can forge a boundary.
const keySep = "\x1f"

// DeriveKeys computes a job's group at every level.
//
// Every key is prefixed with the owner and the job's kind, so an
// estimate for one person is built only from that person's jobs of the
// same kind. A job with no owner gets no keys at all, and so no
// estimate.
func DeriveKeys(f Features) Keys {
	k := Keys{kind: f.Kind()}
	if f.Owner == "" {
		return k
	}
	k.owner = f.Owner
	k.k[LevelOwner] = f.Owner + keySep + k.kind
	o := k.k[LevelOwner] + keySep
	if f.ClusterID > 0 {
		k.k[LevelCluster] = o + strconv.FormatInt(f.ClusterID, 10)
	}
	if cmd, argv := commandKey(f.Cmd, f.Args); cmd != "" {
		k.k[LevelCmd] = o + cmd
		var exact, tmpl strings.Builder
		exact.WriteString(o + cmd)
		tmpl.WriteString(o + cmd)
		for _, a := range argv {
			exact.WriteByte(' ')
			exact.WriteString(normToken(a))
			tmpl.WriteByte(' ')
			tmpl.WriteString(maskToken(a))
		}
		k.k[LevelExact] = exact.String()
		k.k[LevelTemplate] = tmpl.String()
	}
	if b := BatchStem(f.BatchName); b != "" {
		k.k[LevelBatch] = o + b
	}
	if f.Iwd != "" {
		k.k[LevelIwd] = o + maskDigits(f.Iwd)
	}
	return k
}

// interpreters are programs whose identity says little about the work:
// "python" runs everything. For these the key looks through to the
// script or the shell command line.
var interpreters = map[string]bool{
	"bash": true, "sh": true, "python": true, "python3": true, "perl": true,
	"Rscript": true, "julia": true, "apptainer": true, "singularity": true,
	"env": true, "java": true, "matlab": true,
}

// commandKey names the program a job runs and returns the arguments
// that remain once the program has been identified.
//
// The executable is reduced to its basename: a DAG node's Cmd lives
// under a spool directory named for its cluster, and a script copied to
// a new directory is still the same script. For an interpreter the key
// is the interpreter and the script it runs ("python3 train.py"), or,
// for a "-c" command line, the interpreter and "-c" with the command
// line's words as the arguments.
func commandKey(cmd string, args []string) (string, []string) {
	if strings.TrimSpace(cmd) == "" {
		return "", nil
	}
	exe := path.Base(cmd)
	if !interpreters[exe] {
		return exe, args
	}
	container := exe == "apptainer" || exe == "singularity"
	subcommand := false
	for i, a := range args {
		if isCommandFlag(exe, a) {
			return exe + " -c", splitShell(strings.Join(args[i+1:], " "))
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if exe == "env" {
			if _, _, ok := splitAssignment(a); ok {
				continue
			}
		}
		if container && !subcommand && (a == "exec" || a == "run" || a == "shell") {
			subcommand = true
			continue
		}
		return exe + " " + path.Base(a), args[i+1:]
	}
	return exe, args
}

// isCommandFlag reports whether a is the flag that makes the next
// argument a command line: -c, or for a shell a cluster of short flags
// ending in c ("-lc", "-ec").
func isCommandFlag(exe, a string) bool {
	if a == "-c" {
		return true
	}
	if exe != "sh" && exe != "bash" {
		return false
	}
	if len(a) < 3 || a[0] != '-' || a[1] == '-' || a[len(a)-1] != 'c' {
		return false
	}
	for i := 1; i < len(a); i++ {
		if !isLetter(a[i]) {
			return false
		}
	}
	return true
}

// splitShell breaks a shell command line into words. It is not a shell
// parser: quoting is ignored, and operators simply separate words. What
// matters is that the same command line always gives the same words.
func splitShell(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ';', '|', '&', '>', '<':
			return true
		}
		return false
	})
}

// normToken drops what varies between instances of the same job without
// changing what it does: directories, URLs and hashes. Digits stay.
func normToken(t string) string {
	if strings.Contains(t, "://") {
		return "<url>"
	}
	if key, val, ok := splitAssignment(t); ok {
		return key + "=" + normToken(val)
	}
	if strings.Contains(t, "/") {
		t = path.Base(t)
	}
	if isHex(t) && !isNumber(t) {
		return "<HEX>"
	}
	return t
}

// maskToken is normToken with every number masked: a token that is a
// number becomes <N>, and digits inside any other token become <n>.
func maskToken(t string) string {
	if key, val, ok := splitAssignment(t); ok {
		return key + "=" + maskToken(val)
	}
	if isNumber(t) {
		return "<N>"
	}
	return maskDigits(normToken(t))
}

// splitAssignment splits "key=value", "-key=value" or "--key=value",
// where key is an identifier ([A-Za-z_][A-Za-z0-9_.-]*).
func splitAssignment(t string) (key, val string, ok bool) {
	eq := strings.IndexByte(t, '=')
	if eq <= 0 {
		return "", "", false
	}
	key = t[:eq]
	name := key
	for range 2 {
		name = strings.TrimPrefix(name, "-")
	}
	if name == "" || (!isLetter(name[0]) && name[0] != '_') {
		return "", "", false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !isLetter(c) && !isDigit(c) && c != '_' && c != '.' && c != '-' {
			return "", "", false
		}
	}
	return key, t[eq+1:], true
}

// isNumber reports whether t is a decimal number: an optional sign,
// digits, an optional fraction and an optional exponent.
func isNumber(t string) bool {
	i := 0
	if i < len(t) && (t[i] == '+' || t[i] == '-') {
		i++
	}
	start := i
	for i < len(t) && isDigit(t[i]) {
		i++
	}
	if i == start {
		return false
	}
	if i < len(t) && t[i] == '.' {
		i++
		frac := i
		for i < len(t) && isDigit(t[i]) {
			i++
		}
		if i == frac {
			return false
		}
	}
	if i < len(t) && (t[i] == 'e' || t[i] == 'E') {
		i++
		if i < len(t) && (t[i] == '+' || t[i] == '-') {
			i++
		}
		exp := i
		for i < len(t) && isDigit(t[i]) {
			i++
		}
		if i == exp {
			return false
		}
	}
	return i == len(t)
}

// isHex reports whether t is at least eight hex digits: long enough to
// be a hash or an id rather than a word.
func isHex(t string) bool {
	if len(t) < 8 {
		return false
	}
	for i := 0; i < len(t); i++ {
		if !isHexDigit(t[i]) {
			return false
		}
	}
	return true
}

// maskDigits replaces every run of digits with <n>.
func maskDigits(t string) string {
	if strings.IndexFunc(t, func(r rune) bool { return r >= '0' && r <= '9' }) < 0 {
		return t
	}
	var b strings.Builder
	b.Grow(len(t) + 8)
	inRun := false
	for i := 0; i < len(t); i++ {
		if isDigit(t[i]) {
			if !inRun {
				b.WriteString("<n>")
				inRun = true
			}
			continue
		}
		inRun = false
		b.WriteByte(t[i])
	}
	return b.String()
}

// BatchStem strips what makes one submission's JobBatchName different
// from the next one's: trailing runs of digits, and trailing lowercase
// hex runs of eight or more, each with the separator before it.
// "ablation.dag+12111467" becomes "ablation.dag", and
// "htcondor-api-interactive-terminal-8f28ab17adda4631" becomes
// "htcondor-api-interactive-terminal".
func BatchStem(name string) string {
	s := strings.TrimSpace(name)
	for {
		n := trailing(s, isLowerHex)
		if n < 8 {
			n = trailing(s, isDigit)
		}
		if n == 0 {
			return s
		}
		s = s[:len(s)-n]
		if s != "" && strings.IndexByte("-_.+", s[len(s)-1]) >= 0 {
			s = s[:len(s)-1]
		}
	}
}

// trailing is the length of the run at the end of s whose bytes all
// satisfy ok.
func trailing(s string, ok func(byte) bool) int {
	n := 0
	for n < len(s) && ok(s[len(s)-1-n]) {
		n++
	}
	return n
}

func isDigit(c byte) bool    { return c >= '0' && c <= '9' }
func isLetter(c byte) bool   { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
func isLowerHex(c byte) bool { return isDigit(c) || (c >= 'a' && c <= 'f') }
func isHexDigit(c byte) bool { return isLowerHex(c) || (c >= 'A' && c <= 'F') }

// intAttr reads a whole-number attribute, accepting a real: an ad that
// passed through a JSON or a ClassAd round trip may carry 1.7e9 where
// the schedd wrote an integer.
func intAttr(ad *classad.ClassAd, name string) (int64, bool) {
	v, ok := ad.EvaluateAttrNumber(name)
	if !ok || math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, false
	}
	return int64(v), true
}
