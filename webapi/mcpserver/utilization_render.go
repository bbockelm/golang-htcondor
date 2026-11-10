package mcpserver

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/bbockelm/golang-htcondor/webapi/utilization"
)

// Rendering a utilization analysis for a language model: the page's
// answer, compact.
//
// The analysis's full answer carries a histogram, a scatter of up to 400
// jobs and up to 50 batches per workflow, which is what a chart needs and
// far more than a model can use. What a model needs is the headline per
// resource, which workflows the time went to, and every suggestion in a
// form it can act on: the submit lines, what they would save, how sure the
// analysis is, and what they would do for throughput. It renders from the
// same compact form the Utilization page lists from (utilization.Summary)
// and reads one workflow's full detail only for the suggestions it shows
// and the workflow it is asked about, so it can serve from the page's own
// cached answer. The text is bounded so a user with hundreds of workflows
// still gets an answer that fits.

// UtilizationTextLimit bounds the text of one answer. Workflows and
// suggestions beyond it are counted rather than shown.
const UtilizationTextLimit = 16 * 1024

// utilizationTopWorkflows is how many workflows are summarized, by run
// time. Suggestions are listed for every workflow, up to the text bound.
const utilizationTopWorkflows = 10

// UtilizationView says what to render beyond the overview.
type UtilizationView struct {
	// Workflow, when set, picks one workflow to detail: its key, its name,
	// or part of its name or program.
	Workflow string
	// Notes are said before the answer, e.g. why an argument matched
	// nothing.
	Notes []string
}

// UtilizationDetail returns one workflow's full analysis by key, and false
// when there is none.
type UtilizationDetail func(key string) (*utilization.Workflow, bool)

// DetailFromResponse looks workflows up in a full analysis.
func DetailFromResponse(resp *utilization.Response) UtilizationDetail {
	byKey := make(map[string]*utilization.Workflow, len(resp.Workflows))
	for i := range resp.Workflows {
		byKey[resp.Workflows[i].Key] = &resp.Workflows[i]
	}
	return func(key string) (*utilization.Workflow, bool) {
		w, ok := byKey[key]
		return w, ok
	}
}

// peakMemoryNote says once what the memory numbers are, because "used"
// reads as an average and HTCondor records the opposite.
const peakMemoryNote = "Memory is each job's peak -- the most it used at any point, which is what it is held against if it goes over its request. " +
	"Totals are weighted by run time: core-hours, GiB-hours."

// RenderUtilization renders an analysis as text and as structured content.
func RenderUtilization(sum *utilization.Summary, detail UtilizationDetail, view UtilizationView) (string, map[string]interface{}) {
	var b strings.Builder
	for _, n := range view.Notes {
		fmt.Fprintf(&b, "Note: %s\n", n)
	}
	fmt.Fprintf(&b, "Finished jobs in the last %s: %s jobs, %s hours of run time",
		daysPhrase(sum.Days), commas(float64(sum.Overall.Jobs)), commas(sum.Overall.WallHours))
	if sum.Overall.BadputHours > 0 {
		fmt.Fprintf(&b, " (%s hours of it in runs that failed, were removed or were thrown away)", commas(sum.Overall.BadputHours))
	}
	b.WriteString(".\n")
	if sum.Truncated {
		fmt.Fprintf(&b, "Only the most recent %s jobs of the window were analysed; pass a larger limit (at most %s) for more.\n",
			commas(float64(sum.JobsConsidered)), commas(float64(sum.MaxLimit)))
	}
	structured := map[string]interface{}{
		"days":            sum.Days,
		"since":           sum.Since,
		"until":           sum.Until,
		"jobs_considered": sum.JobsConsidered,
		"truncated":       sum.Truncated,
		"limit":           sum.Limit,
		"text_limit":      UtilizationTextLimit,
		"notes":           append([]string{}, view.Notes...),
		"overall":         overallStructured(sum.Overall),
		"workflows_total": len(sum.Workflows),
	}
	if sum.Overall.Jobs == 0 {
		b.WriteString("No finished jobs in this window, so there is nothing to suggest.\n")
		structured["workflows"] = []map[string]interface{}{}
		structured["advice"] = []map[string]interface{}{}
		structured["advice_total"] = 0
		return b.String(), structured
	}
	b.WriteString(peakMemoryNote + "\n")

	workflows := append([]utilization.WorkflowSummary(nil), sum.Workflows...)
	sort.SliceStable(workflows, func(i, j int) bool { return workflows[i].WallHours > workflows[j].WallHours })
	showOwner := len(sum.Owners) > 0
	if view.Workflow != "" {
		// One workflow: its own numbers stand in for the overall ones.
		renderOneWorkflow(&b, structured, workflows, detail, view.Workflow, showOwner)
		return bounded(b.String()), structured
	}

	var lines []string
	for _, r := range sum.Overall.Resources {
		if line := resourceLine(r); line != "" {
			lines = append(lines, "  "+line+"\n")
		}
	}
	if len(lines) > 0 {
		b.WriteString("\nOf what was reserved, how much was used:\n" + strings.Join(lines, ""))
	}
	if g := sum.Overall.ThroughputGain; g != nil && *g > 1.005 {
		fmt.Fprintf(&b, "With every suggestion below, about %sx as many of these jobs could run at once on this pool.\n", ratio(*g))
	}

	top := workflows[:min(len(workflows), utilizationTopWorkflows)]
	fmt.Fprintf(&b, "\nWorkflows by run time (%d of %d):\n", len(top), len(workflows))
	topOut := make([]map[string]interface{}, 0, len(top))
	for _, w := range top {
		b.WriteString("  " + workflowLine(w, showOwner) + "\n")
		topOut = append(topOut, workflowStructured(w))
	}
	structured["workflows"] = topOut

	// Every suggestion, in the analysis's own ranking, up to the bound.
	// The text of each -- detail and submit lines -- is in its workflow's
	// full analysis, read once per workflow shown.
	total := 0
	for _, w := range workflows {
		total += len(w.Advice)
	}
	structured["advice_total"] = total
	adviceOut := []map[string]interface{}{}
	if total == 0 {
		b.WriteString("\nNo suggestions for these jobs.\n")
	} else {
		fmt.Fprintf(&b, "\nSuggestions (%d):\n", total)
	}
	details := map[string]*utilization.Workflow{}
	shownThroughput := map[string]bool{}
	shown := 0
	for _, sg := range sum.Suggestions {
		w, ok := details[sg.Key]
		if !ok {
			w, _ = detail(sg.Key)
			details[sg.Key] = w
		}
		a, w := adviceFor(sg, w)
		var block strings.Builder
		adviceBlock(&block, w, a, !shownThroughput[w.Key])
		if b.Len()+block.Len() > UtilizationTextLimit-300 {
			break
		}
		shownThroughput[w.Key] = true
		b.WriteString(block.String())
		adviceOut = append(adviceOut, adviceStructured(w, a))
		shown++
	}
	if shown < total {
		fmt.Fprintf(&b, "\n%d more suggestion(s) not shown: this answer is limited to %d KiB. "+
			"Ask with workflow set to one workflow's name or key to see its own.\n",
			total-shown, UtilizationTextLimit/1024)
	}
	structured["advice"] = adviceOut
	return b.String(), structured
}

// adviceFor is a ranked suggestion's full advice, from its workflow's
// detail when there is one. Without it the suggestion still has its
// title, savings and confidence; only the detail and submit lines are
// missing.
func adviceFor(sg utilization.Suggestion, w *utilization.Workflow) (utilization.Advice, *utilization.Workflow) {
	if w != nil {
		for _, a := range w.Advice {
			if a.ID == sg.ID {
				return a, w
			}
		}
	}
	if w == nil {
		w = &utilization.Workflow{Key: sg.Key, Name: sg.Name, Executable: sg.Executable, Owner: sg.Owner}
	}
	return utilization.Advice{
		ID: sg.ID, Resource: sg.Resource, Severity: sg.Severity, Title: sg.Title,
		Saves: sg.Saves, Confidence: sg.Confidence,
	}, w
}

// bounded cuts a text at the limit, saying so.
func bounded(s string) string {
	if len(s) <= UtilizationTextLimit {
		return s
	}
	cut := strings.LastIndex(s[:UtilizationTextLimit-120], "\n")
	if cut < 0 {
		cut = UtilizationTextLimit - 120
	}
	return s[:cut] + fmt.Sprintf("\n... cut at %d KiB.\n", UtilizationTextLimit/1024)
}

// renderOneWorkflow is the per-workflow answer: the summary, the
// distributions as percentiles, and all of its suggestions.
func renderOneWorkflow(b *strings.Builder, structured map[string]interface{}, workflows []utilization.WorkflowSummary,
	detail UtilizationDetail, want string, showOwner bool) {
	ws, others := pickWorkflow(workflows, want)
	var w *utilization.Workflow
	if ws != nil {
		w, _ = detail(ws.Key)
	}
	if w == nil {
		fmt.Fprintf(b, "\nNo workflow matches %q. The workflows that ran longest are:\n", want)
		for _, x := range workflows[:min(len(workflows), utilizationTopWorkflows)] {
			b.WriteString("  " + workflowLine(x, showOwner) + "\n")
		}
		structured["workflows"] = []map[string]interface{}{}
		structured["advice"] = []map[string]interface{}{}
		structured["advice_total"] = 0
		return
	}
	fmt.Fprintf(b, "\n%s\n", workflowLine(*ws, showOwner))
	if len(others) > 0 {
		fmt.Fprintf(b, "  (%q also matches: %s)\n", want, strings.Join(others, ", "))
	}
	for _, r := range w.Resources {
		if line := resourceLine(r); line != "" {
			b.WriteString("  " + line + "\n")
		}
	}
	dists := map[string]interface{}{}
	b.WriteString("  Percentiles (p10 / p50 / p90 / p95 / max, over n jobs):\n")
	dist := func(label, key string, d *utilization.Distribution, unit func(float64) string) {
		if d == nil || d.N == 0 {
			return
		}
		fmt.Fprintf(b, "    %s: %s / %s / %s / %s / %s (n=%d)\n", label,
			unit(d.P10), unit(d.P50), unit(d.P90), unit(d.P95), unit(d.Max), d.N)
		dists[key] = map[string]interface{}{
			"n": d.N, "p10": d.P10, "p50": d.P50, "p90": d.P90, "p95": d.P95, "max": d.Max,
		}
	}
	dist("run time", "wall_seconds", w.Wall, duration)
	dist("peak memory", "memory_peak_mib", w.Memory.PeakMiB, mib)
	dist("CPU cores used", "cores_used", w.CPU.CoresUsed, cores)
	dist("CPU efficiency (used / requested)", "cpu_efficiency", w.CPU.Efficiency, pct)
	dist("disk used", "disk_used_kib", w.Disk.UsedKiB, kib)
	if g := w.GPU; g != nil {
		dist("GPU utilization", "gpu_utilization", g.Utilization, pct)
		dist("peak GPU memory", "gpu_memory_peak_mib", g.MemoryPeakMiB, mib)
	}
	var reqs []string
	if r := w.Memory.Request; r != nil {
		reqs = append(reqs, requestPhrase("memory", mib(r.Typical), r.Adaptive))
	}
	if r := w.CPU.Request; r != nil {
		reqs = append(reqs, requestPhrase("CPUs", number(r.Typical), r.Adaptive))
	}
	if r := w.Disk.Request; r != nil {
		reqs = append(reqs, requestPhrase("disk", kib(r.Typical), r.Adaptive))
	}
	if len(reqs) > 0 {
		fmt.Fprintf(b, "  Typical request: %s.\n", strings.Join(reqs, ", "))
	}
	if r := w.Memory.Request; r != nil && r.Adaptive && r.Expression != "" {
		fmt.Fprintf(b, "  RequestMemory = %s\n", r.Expression)
	}
	out := workflowStructured(*ws)
	out["resources"] = resourcesStructured(w.Resources)
	if t := w.Throughput; t != nil {
		out["throughput"] = map[string]interface{}{
			"gain": t.Gain, "fit_current": t.FitCurrent, "fit_suggested": t.FitSuggested, "limited_by": t.LimitedBy,
		}
	}
	out["distributions"] = dists
	structured["workflows"] = []map[string]interface{}{out}
	structured["advice_total"] = len(w.Advice)
	adviceOut := []map[string]interface{}{}
	if len(w.Advice) == 0 {
		b.WriteString("  No suggestions for this workflow.\n")
	}
	for i, a := range w.Advice {
		adviceBlock(b, w, a, i == 0)
		adviceOut = append(adviceOut, adviceStructured(w, a))
	}
	structured["advice"] = adviceOut
}

// requestPhrase says what a request is. A request written as a formula
// over the job's own usage starts at one value and is raised from what
// the job used once it has run; for memory and disk that is after the job
// is held for going over it. The typical value is where it starts.
func requestPhrase(what, value string, adaptive bool) string {
	if !adaptive {
		return what + " " + value
	}
	switch {
	case strings.HasPrefix(what, "memory"):
		return fmt.Sprintf("%s starts at %s and grows after a memory hold", what, value)
	case strings.HasPrefix(what, "disk"):
		return fmt.Sprintf("%s starts at %s and grows after a disk hold", what, value)
	}
	return fmt.Sprintf("%s starts at %s and follows the job's measured use", what, value)
}

// workflowName is what a workflow is called: its batch name, or its
// program when it was submitted without one.
func workflowName(name, executable string) string {
	if name != "" {
		return name
	}
	return executable
}

// pickWorkflow finds the workflow a caller named: by key, then by name,
// then by part of the name or program, the longest-running first. The
// names of other partial matches come back so the caller can be told.
func pickWorkflow(workflows []utilization.WorkflowSummary, want string) (*utilization.WorkflowSummary, []string) {
	for i := range workflows {
		if workflows[i].Key == want {
			return &workflows[i], nil
		}
	}
	lw := strings.ToLower(want)
	for i := range workflows {
		if strings.ToLower(workflowName(workflows[i].Name, workflows[i].Executable)) == lw {
			return &workflows[i], nil
		}
	}
	var hit *utilization.WorkflowSummary
	var others []string
	for i := range workflows {
		w := &workflows[i]
		if strings.Contains(strings.ToLower(w.Name), lw) || strings.Contains(strings.ToLower(w.Executable), lw) {
			if hit == nil {
				hit = w
			} else if len(others) < 5 {
				others = append(others, workflowName(w.Name, w.Executable))
			}
		}
	}
	return hit, others
}

// workflowLine is one workflow in a line.
func workflowLine(w utilization.WorkflowSummary, showOwner bool) string {
	var b strings.Builder
	b.WriteString(workflowName(w.Name, w.Executable))
	if w.IsDAG {
		b.WriteString(" (DAG)")
	}
	if showOwner && w.Owner != "" {
		fmt.Fprintf(&b, " [%s]", w.Owner)
	}
	fmt.Fprintf(&b, " -- key %s, %s jobs", w.Key, commas(float64(w.Jobs)))
	if w.Failed+w.Removed > 0 {
		fmt.Fprintf(&b, " (%d failed, %d removed)", w.Failed, w.Removed)
	}
	fmt.Fprintf(&b, ", %s hours", commas(w.WallHours))
	var used []string
	for _, u := range []struct {
		name string
		f    *float64
	}{{"CPU", w.Used.CPU}, {"memory", w.Used.Memory}, {"disk", w.Used.Disk}, {"GPUs", w.Used.GPU}} {
		if u.f != nil {
			used = append(used, fmt.Sprintf("%s %s", u.name, pct(*u.f)))
		}
	}
	if len(used) > 0 {
		fmt.Fprintf(&b, "; used of reserved: %s", strings.Join(used, ", "))
	}
	if r := w.Request.MemoryMiB; r != nil && slices.Contains(w.Request.Adaptive, utilization.ResourceMemory) {
		fmt.Fprintf(&b, "; %s", requestPhrase("memory request", mib(*r), true))
	}
	if h := w.Holds; h != nil {
		if h.Memory > 0 {
			fmt.Fprintf(&b, "; %d held for memory", h.Memory)
		}
		if h.Disk > 0 {
			fmt.Fprintf(&b, "; %d held for disk", h.Disk)
		}
	}
	if n := len(w.Advice); n > 0 {
		fmt.Fprintf(&b, "; %d suggestion(s)", n)
	}
	return b.String()
}

// adviceBlock renders one suggestion. withThroughput adds the workflow's
// throughput line, once per workflow.
func adviceBlock(b *strings.Builder, w *utilization.Workflow, a utilization.Advice, withThroughput bool) {
	fmt.Fprintf(b, "\n- [%s] %s -- %s\n", a.Severity, workflowName(w.Name, w.Executable), a.Title)
	if a.Detail != "" {
		fmt.Fprintf(b, "  %s\n", oneLineText(a.Detail))
	}
	if len(a.Submit) > 0 {
		b.WriteString("  Submit file:\n")
		for _, line := range a.Submit {
			fmt.Fprintf(b, "    %s\n", line)
		}
	}
	var facts []string
	if a.Saves != nil && a.Saves.Amount > 0 {
		facts = append(facts, "would have saved "+savings(*a.Saves))
	}
	if a.Confidence != "" {
		facts = append(facts, "confidence "+a.Confidence)
	}
	if len(facts) > 0 {
		fmt.Fprintf(b, "  %s\n", capitalize(strings.Join(facts, "; ")))
	}
	if withThroughput {
		if line := throughputLine(w.Throughput); line != "" {
			fmt.Fprintf(b, "  %s\n", line)
		}
	}
}

// throughputLine turns a workflow's throughput estimate into a sentence.
func throughputLine(t *utilization.Throughput) string {
	if t == nil || t.Gain <= 1.005 {
		return ""
	}
	s := fmt.Sprintf("Throughput: with this workflow's suggestions about %sx as many of its jobs could run at once "+
		"(%s at a time now, limited by %s; %s with the suggestions).",
		ratio(t.Gain), commas(float64(t.FitCurrent)), resourceName(t.LimitedBy), commas(float64(t.FitSuggested)))
	if lb := t.LastBatch; lb != nil && lb.Elapsed > 0 {
		s += fmt.Sprintf(" Its last batch of %s jobs took %s; at the suggested requests, about %s.",
			commas(float64(lb.Jobs)), duration(lb.Elapsed), duration(lb.Estimated))
	}
	return s
}

func overallStructured(o utilization.Overall) map[string]interface{} {
	out := map[string]interface{}{
		"jobs":         o.Jobs,
		"wall_hours":   o.WallHours,
		"badput_hours": o.BadputHours,
		"resources":    resourcesStructured(o.Resources),
	}
	if o.ThroughputGain != nil {
		out["throughput_gain"] = *o.ThroughputGain
	}
	return out
}

func resourcesStructured(rs []utilization.ResourceSummary) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(rs))
	for _, r := range rs {
		m := map[string]interface{}{
			"resource":                 r.Resource,
			"allocated_hours":          r.AllocatedHours,
			"allocated_hours_measured": r.AllocatedHoursMeasured,
			"jobs_measured":            r.JobsMeasured,
		}
		if r.UsedHours != nil {
			m["used_hours"] = *r.UsedHours
		}
		if f, ok := usedFraction(r); ok {
			m["used_fraction"] = round3(f)
		}
		out = append(out, m)
	}
	return out
}

func workflowStructured(w utilization.WorkflowSummary) map[string]interface{} {
	m := map[string]interface{}{
		"key":        w.Key,
		"name":       workflowName(w.Name, w.Executable),
		"executable": w.Executable,
		"is_dag":     w.IsDAG,
		"jobs":       w.Jobs,
		"succeeded":  w.Succeeded,
		"failed":     w.Failed,
		"removed":    w.Removed,
		"wall_hours": w.WallHours,
		"advice":     len(w.Advice),
		"used":       w.Used,
		"request":    w.Request,
	}
	if w.Holds != nil {
		m["held_memory"] = w.Holds.Memory
		m["held_disk"] = w.Holds.Disk
	}
	if w.Owner != "" {
		m["owner"] = w.Owner
	}
	if w.Gain != nil {
		m["gain"] = *w.Gain
	}
	return m
}

func adviceStructured(w *utilization.Workflow, a utilization.Advice) map[string]interface{} {
	m := map[string]interface{}{
		"workflow":   w.Key,
		"id":         a.ID,
		"resource":   a.Resource,
		"severity":   a.Severity,
		"title":      a.Title,
		"detail":     a.Detail,
		"submit":     append([]string{}, a.Submit...),
		"confidence": a.Confidence,
	}
	if a.Saves != nil {
		m["saves"] = map[string]interface{}{"unit": a.Saves.Unit, "amount": a.Saves.Amount}
	}
	return m
}

// resourceLine is one resource's used-of-reserved headline.
func resourceLine(r utilization.ResourceSummary) string {
	f, ok := usedFraction(r)
	if !ok {
		if r.AllocatedHours > 0 {
			return fmt.Sprintf("%s: %s reserved; no usage was recorded.", capitalize(resourceName(r.Resource)), resourceHours(r.Resource, r.AllocatedHours))
		}
		return ""
	}
	return fmt.Sprintf("%s: %s used (%s of %s reserved, measured on %s jobs).",
		capitalize(resourceName(r.Resource)), pct(f),
		resourceHours(r.Resource, *r.UsedHours), resourceHours(r.Resource, r.AllocatedHoursMeasured),
		commas(float64(r.JobsMeasured)))
}

// usedFraction is used over the reservation of the jobs that measured it.
func usedFraction(r utilization.ResourceSummary) (float64, bool) {
	if r.UsedHours == nil || r.AllocatedHoursMeasured <= 0 {
		return 0, false
	}
	return *r.UsedHours / r.AllocatedHoursMeasured, true
}

// resourceHours renders a time-weighted amount in the resource's unit:
// the package keeps HTCondor's (MiB of memory, KiB of disk); a person
// reads GiB.
func resourceHours(resource string, v float64) string {
	switch resource {
	case utilization.ResourceCPU:
		return commas(v) + " core-hours"
	case utilization.ResourceMemory:
		return commas(v/1024) + " GiB-hours"
	case utilization.ResourceDisk:
		return commas(v/(1024*1024)) + " GiB-hours"
	case utilization.ResourceGPU:
		return commas(v) + " GPU-hours"
	}
	return commas(v) + " hours"
}

func resourceName(r string) string {
	switch r {
	case utilization.ResourceCPU:
		return "CPU"
	case utilization.ResourceMemory:
		return "memory"
	case utilization.ResourceDisk:
		return "disk"
	case utilization.ResourceGPU:
		return "GPUs"
	case utilization.ResourceRuntime:
		return "run time"
	case "":
		return "nothing in particular"
	}
	return r
}

func savings(s utilization.Savings) string {
	switch s.Unit {
	case utilization.UnitCoreHours:
		return commas(s.Amount) + " core-hours"
	case utilization.UnitGiBHours:
		return commas(s.Amount) + " GiB-hours of memory"
	case utilization.UnitGPUHours:
		return commas(s.Amount) + " GPU-hours"
	}
	return commas(s.Amount) + " " + s.Unit
}

func daysPhrase(days int) string {
	if days == 1 {
		return "day"
	}
	return fmt.Sprintf("%d days", days)
}

// commas renders a number rounded to a sensible precision with thousands
// separators: whole numbers from 100 up, one decimal below.
func commas(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "?"
	}
	if v > 0 && v < 0.01 {
		return "under 0.01"
	}
	if v != 0 && math.Abs(v) < 1 {
		return fmt.Sprintf("%.2g", v)
	}
	if math.Abs(v) < 100 && v != math.Trunc(v) {
		return fmt.Sprintf("%.1f", v)
	}
	n := int64(math.Round(v))
	neg := n < 0
	if neg {
		n = -n
	}
	s := fmt.Sprintf("%d", n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		s = "-" + s
	}
	return s
}

func ratio(x float64) string { return fmt.Sprintf("%.2g", x) }

func pct(f float64) string {
	if f > 0 && f < 0.005 {
		return "under 1%"
	}
	return fmt.Sprintf("%.0f%%", f*100)
}

func number(x float64) string {
	if x == math.Trunc(x) {
		return fmt.Sprintf("%.0f", x)
	}
	return fmt.Sprintf("%.2g", x)
}

func cores(x float64) string { return fmt.Sprintf("%.2g", x) }

func mib(x float64) string {
	if x >= 1024 {
		return fmt.Sprintf("%.1f GiB", x/1024)
	}
	return fmt.Sprintf("%.0f MiB", x)
}

func kib(x float64) string {
	if x < 1024 {
		return fmt.Sprintf("%.0f KiB", x)
	}
	return mib(x / 1024)
}

func duration(seconds float64) string {
	d := time.Duration(seconds) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%.0fs", seconds)
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%.1fd", d.Hours()/24)
}

func round3(x float64) float64 { return math.Round(x*1000) / 1000 }

func oneLineText(s string) string { return strings.Join(strings.Fields(s), " ") }

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// emptyUtilizationResult is the answer for a window with no finished
// jobs. Named so the structured-output contract test can check the empty
// shape without a schedd.
func emptyUtilizationResult() interface{} {
	resp := &utilization.Response{Days: 7, Limit: utilizationToolDefaultLimit}
	text, structured := RenderUtilization(utilization.Summarize(resp), DetailFromResponse(resp), UtilizationView{})
	return structuredTextResult(text, structured)
}
