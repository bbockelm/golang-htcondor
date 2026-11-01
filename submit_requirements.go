package htcondor

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/PelicanPlatform/classad/ast"
	"github.com/PelicanPlatform/classad/classad"
	"github.com/PelicanPlatform/classad/parser"
)

// Requirements is the expression the negotiator matches a job against, and
// condor_submit writes almost all of it: a submit file that names no
// requirements still gets a dozen clauses, because the things a job needs from
// a machine are spread across the submit commands rather than stated in one
// place. request_memory has to become a clause about TARGET.Memory, a docker
// job has to land somewhere with a docker runtime, a job that transfers files
// has to land somewhere that can receive them.
//
// SubmitHash::SetRequirements builds it as TEXT, appending clause by clause in
// a fixed order, and this mirrors that order clause for clause. The order is
// not cosmetic here: the result is one `&&` chain, and reading the two
// expressions against each other is how the difference between them was found.
//
// Two rules run through the whole function.
//
// The first is that a clause is added only when the submitter has not already
// written one about the same machine attribute. The submitter's own
// requirements is parsed, the machine attributes it references are collected,
// and each generated clause is suppressed when its attribute is in that set --
// so `requirements = TARGET.Memory > 8000` replaces the memory clause instead
// of being ANDed with it.
//
// The second is that a clause naming a request attribute is added only when
// the job will carry that attribute, and only when the request asks for more
// than the floor. A clause over an attribute the job does not have evaluates
// to undefined, which makes the whole expression undefined and the job
// unmatchable -- and a clause demanding a machine have at least 1 CPU excludes
// nothing while making every Requirements longer. Hence the literal tests:
// RequestCpus = 1 adds no clause, RequestCpus = 2 does.
func (sf *SubmitFile) setRequirements(ad *classad.ClassAd) error {
	// A forced Requirements -- `MY.Requirements` or `+Requirements` -- is the
	// whole expression. SetRequirements returns the moment it finds one,
	// leaving what SetForcedAttributes put on the ad, and warns when the file
	// also used the `requirements` keyword because only one of them can win.
	//
	// generatesRequirements is the same question finalizeCUDAVersion asks, and
	// they have to agree: the CUDA clause and the CUDA conversion both belong
	// to the generated expression, so a job that takes none must get neither.
	if forced, ok := sf.customAttrValue("Requirements"); ok && strings.TrimSpace(forced) != "" {
		return nil
	}

	var answer string
	userReq, hasUserReq := sf.submitCommand("requirements")
	if hasUserReq {
		answer = "(" + userReq + ")"
	} else if factoryReq, ok := sf.submitCommand("FACTORY.Requirements"); ok {
		// A factory's own requirements replaces the generation entirely.
		if strings.EqualFold(strings.TrimSpace(factoryReq), "MY.Requirements") {
			if _, ok := ad.Lookup("Requirements"); !ok {
				return fmt.Errorf("'Requirements = MY.Requirements' when there are not yet any Requirements")
			}
			return nil
		}
		return sf.assignRequirements(ad, factoryReq)
	}

	answer = sf.appendConfiguredRequirements(answer)

	// A grid job bound for anything but Condor-C takes no generated clauses at
	// all: the machine it lands on is the remote system's business, and
	// TARGET here is not an HTCondor slot ad.
	if sf.universe == UniverseGrid {
		res, _ := sf.submitCommandAlt("grid_resource", "GridResource")
		gridType, _, _ := strings.Cut(strings.TrimSpace(res), " ")
		generate := parseBool(sf.paramOr("SUBMIT_GENERATE_CONDOR_C_REQUIREMENTS", "true"), true)
		if !strings.EqualFold(gridType, "condor") || !generate {
			if answer == "" {
				answer = "TRUE"
			}
			return sf.assignRequirements(ad, answer)
		}
	}

	refs := machineRefs(answer)
	isDocker, isContainer, err := sf.containerJobRoles()
	if err != nil {
		return err
	}

	add := func(clause string) {
		if answer != "" {
			answer += " && "
		}
		answer += clause
	}

	sf.addPlatformRequirements(ad, refs, add, isDocker, isContainer)

	sf.addDiskRequirement(ad, refs, add)
	sf.addMemoryRequirement(ad, refs, add)
	sf.addCpusRequirement(ad, refs, add)
	addCustomResourceRequirements(ad, refs, add, sf.generateCustomResourceRequirements())

	// A job with a tool daemon needs a starter that can run one.
	if !refs["hastdp"] {
		if _, ok := ad.Lookup("ToolDaemonCmd"); ok {
			add("TARGET.HasTDP")
		}
	}
	if !refs["encryptexecutedirectory"] && boolAttr(ad, "EncryptExecuteDirectory") {
		add("TARGET.HasEncryptExecuteDirectory")
	}

	answer = sf.appendTransferRequirements(ad, refs, answer)

	if err := sf.addDeferralRequirement(ad, &answer); err != nil {
		return err
	}

	// The starter only transfers a checkpoint for a job that asked, and only
	// if it knows how.
	if boolAttr(ad, "WantFTOnCheckpoint") && !refs["hasselfcheckpointtransfers"] {
		if answer != "" {
			answer += " && "
		}
		answer += "TARGET.HasSelfCheckpointTransfers"
	}

	// A cuda_version the job asked for has to be one the machine's driver
	// supports. finalizeCUDAVersion owns both halves of this; see cudaClause.
	if sf.cudaClause {
		if answer != "" {
			answer += " && "
		}
		answer += "CUDAVersion <= TARGET.CUDAMaxSupportedVersion"
	}

	if boolAttr(ad, "OCUWanted") {
		if answer != "" {
			answer += " && "
		}
		answer += "TARGET.OCU =?= true"
	}

	return sf.assignRequirements(ad, answer)
}

// addPlatformRequirements adds the clauses that put the job on a machine that
// can run its executable at all: the submitting machine's platform, and
// whatever runtime the universe needs.
//
// Arch and OpSys are pinned to VALUES rather than merely required to be
// defined, because a submit host's binaries do not run on another platform. A
// container or docker job counts as having checked OpSys, since its image
// carries its own.
func (sf *SubmitFile) addPlatformRequirements(ad *classad.ClassAd, refs map[string]bool, add func(string), isDocker, isContainer bool) {
	checksArch := refs["arch"]
	checksOpSys := isContainer || isDocker || refs["opsys"] || refs["opsysandver"] ||
		refs["opsyslongname"] || refs["opsysshortname"] || refs["opsysname"] ||
		refs["opsyslegacy"]

	switch {
	case sf.universe == UniverseJava:
		add("TARGET.HasJava")
	case sf.universe == UniverseVM:
		if !checksArch {
			add(fmt.Sprintf("(TARGET.Arch == %q)", sf.submitArch()))
		}
		if !refs["hasvm"] {
			add("(TARGET.HasVM =?= true)")
		}
		if !refs["vm_type"] {
			add("(TARGET.VM_Type == MY.JobVMType)")
		}
		if !refs["vm_availnum"] {
			add("(TARGET.VM_AvailNum > 0)")
		}
		if boolAttr(ad, "JobVMCheckpoint") && !refs["vm_ckptmac"] {
			add("((MY.VM_CkptMac =?= UNDEFINED) || (TARGET.VM_All_Guest_Macs =?= UNDEFINED) " +
				"|| (stringListIMember(MY.VM_CkptMac, TARGET.VM_All_Guest_Macs, \",\") == FALSE))")
		}
	case isDocker:
		if !checksArch {
			add(fmt.Sprintf("(TARGET.Arch == %q)", sf.submitArch()))
		}
		add("TARGET.HasDocker")
		if net, ok := ad.EvaluateAttrString("DockerNetworkType"); ok && net != "" {
			// host, none and nat are assumed of every runtime and not
			// advertised, so matching on them would exclude everything.
			switch net {
			case "host", "none", "nat":
			default:
				add("StringListMember(My.DockerNetworkType, TARGET.DockerNetworks)")
			}
		}
	case isContainer:
		if !checksArch {
			add(fmt.Sprintf("(TARGET.Arch == %q)", sf.submitArch()))
		}
		add("TARGET.HasContainer")
		if _, ok := ad.Lookup("DockerImage"); ok {
			add("TARGET.HasDockerURL")
		} else if img, ok := ad.EvaluateAttrString("ContainerImage"); ok && img != "" {
			add(containerImageRequirement(img))
		}
	default:
		if !checksArch {
			add(fmt.Sprintf("(TARGET.Arch == %q)", sf.submitArch()))
		}
		if !checksOpSys {
			add(fmt.Sprintf("(TARGET.OpSys == %q)", sf.submitOpSys()))
		}
	}

}

// appendConfiguredRequirements adds the pool's own clause, from
// FACTORY.AppendReq or whichever APPEND_REQ* knob applies to the universe.
func (sf *SubmitFile) appendConfiguredRequirements(answer string) string {
	if factory, ok := sf.submitCommand("FACTORY.AppendReq"); ok && factory != "" {
		if answer != "" {
			answer += " && "
		}
		if strings.HasPrefix(factory, "(") {
			return answer + factory
		}
		return answer + "(" + factory + ")"
	}

	var appendReq string
	switch sf.universe {
	case UniverseVanilla:
		appendReq, _ = sf.param("APPEND_REQ_VANILLA")
	case UniverseVM:
		appendReq, _ = sf.param("APPEND_REQ_VM")
	}
	if appendReq == "" {
		appendReq, _ = sf.param("APPEND_REQUIREMENTS")
	}
	if appendReq == "" {
		return answer
	}
	if answer != "" {
		return answer + " && (" + appendReq + ")"
	}
	return "(" + appendReq + ")"
}

// addDiskRequirement adds the disk clause.
//
// A sufficiently recent starter adjusts RequestDisk itself to account for
// common files, so for a vanilla job the clause defers to the machine's
// version rather than enforcing the request the submitter asked for -- which
// is why this one clause carries a versionGE test and the others do not.
func (sf *SubmitFile) addDiskRequirement(ad *classad.ClassAd, refs map[string]bool, add func(string)) {
	if refs["disk"] {
		// The submitter named TARGET.Disk themselves. The request clause is
		// still added, because their clause is about the machine and this one
		// is about the request.
		if sf.universe != UniverseVM {
			if _, ok := ad.Lookup("RequestDisk"); ok {
				add("(TARGET.Disk >= RequestDisk)")
			}
		}
		return
	}

	expr, ok := ad.Lookup("RequestDisk")
	switch {
	case ok:
		if n, literal := literalNumber(expr); literal && n <= 0 {
			return
		}
		if sf.universe == UniverseVanilla {
			add("(versionGE(split(TARGET.CondorVersion)[1], \"25.12.0\") || (TARGET.Disk >= RequestDisk))")
		} else {
			add("(TARGET.Disk >= RequestDisk)")
		}
	case sf.universe == UniverseVM:
		// A VM's disk is the whole slot's, not the slot's share.
		add("(TARGET.TotalDisk >= DiskUsage)")
	default:
		add("(TARGET.Disk >= DiskUsage)")
	}
}

// addMemoryRequirement adds the memory clause, which for a VM job is a family
// of clauses about the VM's own memory instead.
func (sf *SubmitFile) addMemoryRequirement(ad *classad.ClassAd, refs map[string]bool, add func(string)) {
	if sf.universe == UniverseVM {
		vmType, _ := ad.EvaluateAttrString("JobVMType")
		if !strings.EqualFold(vmType, "xen") {
			add("(TARGET.TotalMemory >= MY.JobVMMemory)")
		}
		if !refs["vm_memory"] {
			add("(TARGET.VM_Memory >= MY.JobVMMemory)")
		}
		if boolAttr(ad, "JobVMHardwareVT") && !refs["vm_hardwarevt"] {
			add("TARGET.VM_HardwareVT")
		}
		if boolAttr(ad, "JobVMNetworking") {
			if !refs["vm_networking"] {
				add("TARGET.VM_Networking")
			}
			if _, ok := ad.Lookup("JobVMNetworkingType"); ok {
				add("stringListIMember(JobVMNetworkingType,TARGET.VM_Networking_Types,\",\")")
			}
		}
		return
	}

	expr, ok := ad.Lookup("RequestMemory")
	if !ok {
		return
	}
	if n, literal := literalNumber(expr); literal && n <= 1.0 {
		return
	}
	add("(TARGET.Memory >= RequestMemory)")
}

// addCpusRequirement adds the CPU clause. A grid job takes none: the remote
// system allocates its own CPUs.
func (sf *SubmitFile) addCpusRequirement(ad *classad.ClassAd, refs map[string]bool, add func(string)) {
	if sf.universe == UniverseGrid || refs["cpus"] {
		return
	}
	expr, ok := ad.Lookup("RequestCpus")
	if !ok {
		return
	}
	if n, literal := literalNumber(expr); literal && n <= 1.0 {
		return
	}
	add("(TARGET.Cpus >= RequestCpus)")
}

// addCustomResourceRequirements adds a clause for every Request<Tag> on the ad
// that is not one of the three handled above -- RequestGpus included, which is
// why there is no GPU-specific clause anywhere in this file.
//
// A tag with a Require<Tag> expression beside it is matched with countMatches
// against the machine's Available<Tag> list, which is how require_gpus selects
// one GPU out of several on a machine rather than merely counting them.
func addCustomResourceRequirements(ad *classad.ClassAd, refs map[string]bool, add func(string), custom bool) {
	const prefix = "Request"
	var tags []string
	for _, name := range ad.GetAttributes() {
		if len(name) < len(prefix)+2 || !strings.EqualFold(name[:len(prefix)], prefix) {
			continue
		}
		if name[len(prefix)] == '_' {
			continue
		}
		switch strings.ToLower(name) {
		case "requestcpus", "requestdisk", "requestmemory":
			continue
		}
		if !custom && !strings.EqualFold(name, "RequestGpus") {
			continue
		}
		tags = append(tags, name)
	}
	sort.Strings(tags)

	for _, name := range tags {
		tag := name[len(prefix):]
		if refs[strings.ToLower(tag)] {
			continue
		}
		expr, ok := ad.Lookup(name)
		if !ok {
			continue
		}
		if s, isString := literalString(expr); isString {
			// An empty string requests nothing.
			if s != "" {
				add(fmt.Sprintf("regexp(%s, TARGET.%s)", name, tag))
			}
			continue
		}
		// A number at or below zero requests nothing. An expression, which
		// has no number to test, always gets its clause.
		if n, literal := literalNumber(expr); literal && n <= 0 {
			continue
		}
		if _, ok := ad.Lookup("Require" + tag); ok {
			add(fmt.Sprintf("(countMatches(MY.Require%s,TARGET.Available%s) >= %s)", tag, tag, name))
			continue
		}
		add(fmt.Sprintf("(TARGET.%s >= %s)", tag, name))
	}
}

// appendTransferRequirements adds the clauses that put the job somewhere it
// can get its files, for the universes that might transfer any.
//
// The shape is a single parenthesised group whose two halves are ORed: the
// machine shares the submitter's filesystem, OR the machine can transfer.
// With should_transfer_files = YES only the transfer half is written, and with
// NO only the filesystem half -- the job has said it will not transfer, so the
// only way it can reach its files is a shared filesystem.
func (sf *SubmitFile) appendTransferRequirements(ad *classad.ClassAd, refs map[string]bool, answer string) string {
	if !mightTransfer(sf.universe) {
		return answer
	}

	const domainCheck = "(TARGET.FileSystemDomain == MY.FileSystemDomain)"
	xferCheck := "TARGET.HasFileTransfer"
	if plugins, ok := ad.EvaluateAttrString("TransferPlugins"); ok && plugins != "" {
		xferCheck = "TARGET.HasJobTransferPlugins"
	}
	cryptCheck := ""
	if !refs["hasperfileencryption"] && anyAttr(ad, "EncryptInputFiles", "EncryptOutputFiles",
		"DontEncryptInputFiles", "DontEncryptOutputFiles") {
		cryptCheck = " && TARGET.HasPerFileEncryption"
	}

	checksFSDomain := refs["filesystemdomain"]
	checksFileTransfer := refs["hasfiletransfer"] || refs["hasjobtransferplugins"]

	should := stfIfNeeded
	if s, ok := ad.EvaluateAttrString("ShouldTransferFiles"); ok {
		if v, valid := shouldTransferFilesNum(s); valid {
			should = v
		}
	}

	if should == stfNo {
		if !checksFSDomain {
			answer += " && " + domainCheck
		}
		return answer
	}
	if checksFileTransfer {
		return answer
	}

	joinOp, closeOp := " && (", ")"
	if should == stfIfNeeded && !checksFSDomain {
		answer += joinOp + domainCheck
		joinOp, closeOp = " || (", "))"
	}
	answer += joinOp + xferCheck + cryptCheck

	// Three features need a starter new enough to have them.
	addVersionCheck := false
	// TransferCheckpoint, which is what ATTR_CHECKPOINT_FILES spells -- the
	// attribute is not named after its keyword.
	if s, ok := ad.EvaluateAttrString("TransferCheckpoint"); ok && s != "" {
		addVersionCheck = true
	}
	if boolAttr(ad, "PreserveRelativePaths") {
		addVersionCheck = true
	}
	if when, ok := ad.EvaluateAttrString("WhenToTransferOutput"); ok {
		if v, valid := fileTransferOutputNum(when); valid && v == ftoOnSuccess {
			addVersionCheck = true
		}
	}
	if addVersionCheck {
		answer += " && versioncmp( split(TARGET.CondorVersion)[1], \"8.9.7\" ) >= 0"
	}

	if boolAttr(ad, "RequireCommonFilesTransfer") {
		answer += " && TARGET.HasCommonFilesTransfer >= 2"
	}

	// One clause per transfer method the job needs and does not supply
	// itself. WantTransferPluginMethods already holds exactly that set.
	if !refs["hasfiletransferpluginmethods"] {
		if methods, ok := ad.EvaluateAttrString("WantTransferPluginMethods"); ok && methods != "" {
			for _, m := range strings.Split(methods, ",") {
				if m = strings.TrimSpace(m); m != "" {
					answer += fmt.Sprintf(" && stringListIMember(%q,TARGET.HasFileTransferPluginMethods)", m)
				}
			}
		}
	}

	return answer + closeOp
}

// addDeferralRequirement adds the clauses a deferred job needs: a starter that
// can defer, and a window test that keeps the job from being matched before
// its start time is near or after the window has passed.
//
// The window test names ScheddInterval, so the attribute has to be on the ad
// for the expression to evaluate -- which is the only reason condor_submit
// writes it, and the only reason this does.
func (sf *SubmitFile) addDeferralRequirement(ad *classad.ClassAd, answer *string) error {
	deferred := false
	for _, attr := range deferralTriggerAttrs {
		if _, ok := ad.Lookup(attr); ok {
			deferred = true
			break
		}
	}
	if !deferred {
		return nil
	}

	if sf.universe != UniverseLocal {
		if *answer != "" {
			*answer += " && "
		}
		*answer += "TARGET.HasJobDeferral"
	}

	if _, ok := ad.Lookup("ScheddInterval"); !ok {
		interval, _ := sf.param("SCHEDD_INTERVAL")
		if strings.TrimSpace(interval) == "" {
			interval = strconv.Itoa(scheddIntervalDefault)
		}
		if err := setExprAttr(ad, "ScheddInterval", "SCHEDD_INTERVAL", interval); err != nil {
			return err
		}
	}

	if *answer != "" {
		*answer += " && "
	}
	*answer += "(((time() + ScheddInterval) >= (DeferralTime - DeferralPrepTime)) && " +
		"(time() < (DeferralTime + DeferralWindow)))"
	return nil
}

// assignRequirements parses the assembled text and stores it.
//
// An empty expression becomes TRUE rather than nothing. condor_submit never
// produces a job without Requirements, and the difference matters off the
// matchmaking path: a schedd can carry a SUBMIT_REQUIREMENT_<name> that
// references the job's Requirements, and an absent attribute makes it evaluate
// to undefined rather than false. The OSPool access point has one --
// `SUBMIT_REQUIREMENT_ModulesWarning = ! unresolved(Requirements, "HAS_MODULES")`
// -- and `! undefined` is not a boolean, so the schedd refused the whole
// transaction with "evaluated to non-boolean". Every DAGMan submission to such
// an access point failed, because the manager job is exactly the job that
// reaches here with nothing to require.
func (sf *SubmitFile) assignRequirements(ad *classad.ClassAd, answer string) error {
	if strings.TrimSpace(answer) == "" {
		answer = "true"
	}
	expr, err := classad.ParseExpr(answer)
	if err != nil {
		return fmt.Errorf("failed to parse requirements expression %q: %w", answer, err)
	}
	_ = ad.Set("Requirements", expr)
	return nil
}

// mightTransfer is the mightTransfer() of condor_utils: the universes whose
// jobs may use file transfer or a shared filesystem. A scheduler- or
// local-universe job is run by the schedd itself and matched against the
// SCHEDD's ad, which advertises no HasFileTransfer at all -- so a transfer
// clause there is undefined, Requirements goes false, and the job sits Idle
// forever with nothing in the log but "SchedUniverseJobsIdle = 1".
func mightTransfer(universe int) bool {
	switch universe {
	case UniverseVanilla, UniverseJava, UniverseParallel, UniverseVM:
		return true
	}
	return false
}

// machineRefs collects the machine attributes an expression references,
// classified as GetExprReferences classifies them for SetRequirements: a
// TARGET-scoped reference is a machine attribute, an unqualified one is too
// unless it names one of the job attributes condor_submit seeds into its
// scratch ad, and a MY-scoped one is the job's own. Names come back folded,
// since ClassAd attribute names are case-insensitive.
//
// An expression that does not parse contributes no references, which is the
// safe direction: every generated clause is then still added, and the
// submitter's unparsable requirements fails later where the error can name it.
func machineRefs(expr string) map[string]bool {
	refs := map[string]bool{}
	if strings.TrimSpace(expr) == "" {
		return refs
	}
	tree, err := parser.ParseExpr(expr)
	if err != nil || tree == nil {
		return refs
	}
	collectMachineRefs(tree, refs)
	return refs
}

// seededJobAttrs are the attributes condor_submit puts in its scratch ad
// before collecting references, which makes an unqualified mention of one of
// them a reference to the JOB rather than to a machine.
var seededJobAttrs = map[string]bool{
	"requestmemory": true,
	"vm_ckptmac":    true,
	"requirements":  true,
}

func collectMachineRefs(expr ast.Expr, refs map[string]bool) {
	switch v := expr.(type) {
	case *ast.ParenExpr:
		collectMachineRefs(v.Inner, refs)
	case *ast.AttributeReference:
		name := strings.ToLower(v.Name)
		switch v.Scope {
		case ast.TargetScope:
			refs[name] = true
		case ast.NoScope:
			if !seededJobAttrs[name] {
				refs[name] = true
			}
		}
	case *ast.BinaryOp:
		collectMachineRefs(v.Left, refs)
		collectMachineRefs(v.Right, refs)
	case *ast.UnaryOp:
		collectMachineRefs(v.Expr, refs)
	case *ast.ConditionalExpr:
		collectMachineRefs(v.Condition, refs)
		collectMachineRefs(v.TrueExpr, refs)
		collectMachineRefs(v.FalseExpr, refs)
	case *ast.ElvisExpr:
		collectMachineRefs(v.Left, refs)
		collectMachineRefs(v.Right, refs)
	case *ast.FunctionCall:
		for _, arg := range v.Args {
			collectMachineRefs(arg, refs)
		}
	case *ast.ListLiteral:
		for _, elem := range v.Elements {
			collectMachineRefs(elem, refs)
		}
	case *ast.ClassAd:
		for _, attr := range v.Attributes {
			collectMachineRefs(attr.Value, refs)
		}
	case *ast.SelectExpr:
		collectMachineRefs(v.Record, refs)
	case *ast.SubscriptExpr:
		collectMachineRefs(v.Container, refs)
		collectMachineRefs(v.Index, refs)
	}
}

// literalNumber reports the value of an expression that is a bare number,
// which is ExprTreeIsLiteralNumber: an expression that merely evaluates to a
// number is not one, because the clauses that test this are deciding whether
// the submitter asked for more than the floor and an expression's value is not
// known at submit time.
func literalNumber(expr *classad.Expr) (float64, bool) {
	if expr == nil {
		return 0, false
	}
	n, err := strconv.ParseFloat(strings.TrimSpace(expr.String()), 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// literalString reports the value of an expression that is a quoted string.
func literalString(expr *classad.Expr) (string, bool) {
	if expr == nil {
		return "", false
	}
	text := strings.TrimSpace(expr.String())
	if len(text) < 2 || text[0] != '"' || text[len(text)-1] != '"' {
		return "", false
	}
	s, err := strconv.Unquote(text)
	if err != nil {
		return text[1 : len(text)-1], true
	}
	return s, true
}

// boolAttr reports whether an attribute is on the ad and evaluates true.
func boolAttr(ad *classad.ClassAd, attr string) bool {
	v, ok := ad.EvaluateAttrBool(attr)
	return ok && v
}

// anyAttr reports whether any of the named attributes is on the ad.
func anyAttr(ad *classad.ClassAd, attrs ...string) bool {
	for _, attr := range attrs {
		if _, ok := ad.Lookup(attr); ok {
			return true
		}
	}
	return false
}

// containerImageRequirement is the execute-node capability an image kind needs,
// which is image_type_from_string's classification. SetRequirements writes it
// bare -- `&& TARGET.HasSIF` -- where the container want-flag path writes the
// `=?= true` form, so the two spellings are kept apart deliberately.
func containerImageRequirement(image string) string {
	switch _, capability := containerImageKind(image); capability {
	case "TARGET.HasDockerURL =?= true":
		return "TARGET.HasDockerURL"
	case "TARGET.HasSIF =?= true":
		return "TARGET.HasSIF"
	default:
		return "TARGET.HasSandboxImage"
	}
}

// generateCustomResourceRequirements reports whether clauses are generated for
// custom resources other than GPUs.
func (sf *SubmitFile) generateCustomResourceRequirements() bool {
	return parseBool(sf.paramOr("SUBMIT_GENERATE_CUSTOM_RESOURCE_REQUIREMENTS", "true"), true)
}

// paramOr is param with a fallback for a knob the configuration does not carry.
func (sf *SubmitFile) paramOr(name, def string) string {
	if v, ok := sf.param(name); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

// scheddIntervalDefault is SCHEDD_INTERVAL_DEFAULT (condor_utils/submit_utils.h),
// used when the configuration carries no SCHEDD_INTERVAL for the deferral
// window expression to name.
const scheddIntervalDefault = 300

// submitArch and submitOpSys are the submitting machine's platform, which is
// what condor_submit requires of a machine rather than merely requiring the
// attributes to be defined: ARCH and OPSYS as the configuration resolves them,
// the same values ArchMacroDef and OpsysMacroDef hold there.
func (sf *SubmitFile) submitArch() string {
	v, _ := sf.cfg.Get("ARCH")
	return v
}

func (sf *SubmitFile) submitOpSys() string {
	v, _ := sf.cfg.Get("OPSYS")
	return v
}
