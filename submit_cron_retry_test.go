package htcondor

import (
	"strings"
	"testing"
)

// cronRetryAd builds the proc-0 job ad for a submit file and returns a
// lookup that gives each attribute's expression text. A parse or build
// failure is fatal, since every case here is a submit file condor_submit
// accepts.
func cronRetryAd(t *testing.T, submit string) func(string) (string, bool) {
	t.Helper()
	sf, err := ParseSubmitFile(strings.NewReader(submit))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ad, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, map[string]string{})
	if err != nil {
		t.Fatalf("make job ad: %v", err)
	}
	return func(attr string) (string, bool) {
		expr, ok := ad.Lookup(attr)
		if !ok || expr == nil {
			return "", false
		}
		return expr.String(), true
	}
}

func wantAttrs(t *testing.T, get func(string) (string, bool), want map[string]string) {
	t.Helper()
	for attr, value := range want {
		got, ok := get(attr)
		if !ok {
			t.Errorf("%s is missing; want %s", attr, value)
			continue
		}
		if got != value {
			t.Errorf("%s = %s; want %s", attr, got, value)
		}
	}
}

func wantNoAttrs(t *testing.T, get func(string) (string, bool), attrs ...string) {
	t.Helper()
	for _, attr := range attrs {
		if got, ok := get(attr); ok {
			t.Errorf("%s is set to %s; it should not be set at all", attr, got)
		}
	}
}

// TestCronWindowIsDeferralWindow pins the mapping that makes a cron job
// actually defer. cron_window and cron_prep_time name DeferralWindow and
// DeferralPrepTime; there are no CronWindow or CronPrepTime job attributes
// for the starter to read.
func TestCronWindowIsDeferralWindow(t *testing.T) {
	get := cronRetryAd(t, `
executable = /bin/sleep
cron_minute = 0
cron_hour = */2
cron_day_of_month = *
cron_month = *
cron_day_of_week = *
cron_window = 600
cron_prep_time = 300
`)
	wantAttrs(t, get, map[string]string{
		"CronMinute":       `"0"`,
		"CronHour":         `"*/2"`,
		"CronDayOfMonth":   `"*"`,
		"CronMonth":        `"*"`,
		"CronDayOfWeek":    `"*"`,
		"DeferralWindow":   "600",
		"DeferralPrepTime": "300",
	})
	wantNoAttrs(t, get, "CronWindow", "CronPrepTime")
}

// TestCronScheduleDefaultsDeferralTiming: a deferred job always carries both
// timing attributes, defaulted when the submit file says nothing.
func TestCronScheduleDefaultsDeferralTiming(t *testing.T) {
	get := cronRetryAd(t, "executable = /bin/sleep\ncron_minute = 0\n")
	wantAttrs(t, get, map[string]string{
		"DeferralWindow":   "0",
		"DeferralPrepTime": "300",
	})
}

// TestDeferralTimingNeedsASchedule: the timing attributes belong to a
// deferred job. Without a schedule or a deferral_time there is nothing to
// defer, and condor_submit writes neither attribute.
func TestDeferralTimingNeedsASchedule(t *testing.T) {
	get := cronRetryAd(t, "executable = /bin/sleep\ncron_window = 60\ncron_prep_time = 30\n")
	wantNoAttrs(t, get, "DeferralWindow", "DeferralPrepTime", "CronWindow", "CronPrepTime")
}

// TestCronWindowWinsOverDeferralWindow pins which spelling wins when a file
// uses both, and that the alternate spellings reach the same attribute.
func TestCronWindowWinsOverDeferralWindow(t *testing.T) {
	get := cronRetryAd(t, `
executable = /bin/sleep
cron_minute = 0
cron_window = 60
deferral_window = 999
cron_prep_time = 30
deferral_prep_time = 999
`)
	wantAttrs(t, get, map[string]string{"DeferralWindow": "60", "DeferralPrepTime": "30"})

	alt := cronRetryAd(t, "executable = /bin/sleep\ncron_minute = 0\ndeferral_window = 7\nCronWindow = 9\n")
	wantAttrs(t, alt, map[string]string{"DeferralWindow": "9"})
}

// TestDeferralTimeIsAnExpression: deferral timing is evaluated by the
// starter, so `(time() + 3600)` has to survive as an expression rather than
// being parsed as an integer and dropped.
func TestDeferralTimeIsAnExpression(t *testing.T) {
	get := cronRetryAd(t, "executable = /bin/sleep\ndeferral_time = (time() + 3600)\n")
	if got, ok := get("DeferralTime"); !ok || !strings.Contains(got, "time()") {
		t.Errorf("DeferralTime = %q (present=%v); want the time() expression", got, ok)
	}
}

// TestDeferralRejectsNegativeTiming: a literal timing value has to be a
// non-negative integer, and condor_submit fails the file when it is not.
func TestDeferralRejectsNegativeTiming(t *testing.T) {
	for _, submit := range []string{
		"executable = /bin/sleep\ncron_minute = 0\ncron_window = -1\n",
		"executable = /bin/sleep\ncron_minute = 0\ncron_window = 1.5\n",
		"executable = /bin/sleep\ndeferral_time = -5\n",
	} {
		sf, err := ParseSubmitFile(strings.NewReader(submit))
		if err != nil {
			t.Fatalf("parse %q: %v", submit, err)
		}
		if _, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, map[string]string{}); err == nil {
			t.Errorf("%q was accepted; condor_submit rejects it", submit)
		}
	}
}

// TestMaxRetriesBuildsOnExitRemove is the heart of the retry family: the
// setting has to land in JobMaxRetries, and OnExitRemove has to become the
// expression that keeps the job around to be retried.
func TestMaxRetriesBuildsOnExitRemove(t *testing.T) {
	get := cronRetryAd(t, "executable = /bin/sleep\nmax_retries = 3\n")
	wantAttrs(t, get, map[string]string{
		"JobMaxRetries": "3",
		"OnExitRemove":  "((NumJobCompletions > JobMaxRetries) || (ExitCode is 0))",
		"OnExitHold":    "false",
	})
	wantNoAttrs(t, get, "MaxRetries")
}

// TestRetryUntilIsFoldedIntoOnExitRemove: retry_until is not a job attribute.
// A constant becomes a futility exit code; anything naming an attribute is
// used as the expression it is. Either way it ends up inside OnExitRemove,
// and retries are enabled even though max_retries was never given.
func TestRetryUntilIsFoldedIntoOnExitRemove(t *testing.T) {
	code := cronRetryAd(t, "executable = /bin/sleep\nretry_until = 42\n")
	wantAttrs(t, code, map[string]string{
		"JobMaxRetries": "2",
		"OnExitRemove":  "(((NumJobCompletions > JobMaxRetries) || (ExitCode is 0)) || (ExitCode is 42))",
	})
	wantNoAttrs(t, code, "RetryUntil")

	expr := cronRetryAd(t, "executable = /bin/sleep\nretry_until = ExitCode == 7\n")
	wantAttrs(t, expr, map[string]string{
		"OnExitRemove": "(((NumJobCompletions > JobMaxRetries) || (ExitCode is 0)) || (ExitCode == 7))",
	})
	wantNoAttrs(t, expr, "RetryUntil")
}

// TestRetryUntilConstantsAreEvaluated: the futility code is whatever the
// value evaluates to, not what it is spelled as, so `1+1` and `true` are
// exit codes 2 and 1.
func TestRetryUntilConstantsAreEvaluated(t *testing.T) {
	for value, want := range map[string]string{"1+1": "2", "true": "1", "1.9": "1", "-1": "(-1)"} {
		get := cronRetryAd(t, "executable = /bin/sleep\nretry_until = "+value+"\n")
		got, ok := get("OnExitRemove")
		if !ok || !strings.Contains(got, "ExitCode is "+want) {
			t.Errorf("retry_until = %s gave OnExitRemove = %q; want a futility code of %s", value, got, want)
		}
	}
}

// TestOnExitRemoveIsOrdOntoTheRetryExpression: the submitter's own
// on_exit_remove does not survive on its own under retries. Keeping it would
// remove the job on its first failure, so it would never be retried.
func TestOnExitRemoveIsOrdOntoTheRetryExpression(t *testing.T) {
	get := cronRetryAd(t, "executable = /bin/sleep\nmax_retries = 3\non_exit_remove = ExitCode == 0\n")
	wantAttrs(t, get, map[string]string{
		"OnExitRemove": "(((NumJobCompletions > JobMaxRetries) || (ExitCode is 0)) || (ExitCode == 0))",
	})

	// Without any retry setting it is stored as written.
	plain := cronRetryAd(t, "executable = /bin/sleep\non_exit_remove = ExitCode == 0\n")
	wantAttrs(t, plain, map[string]string{"OnExitRemove": "(ExitCode == 0)"})
	wantNoAttrs(t, plain, "JobMaxRetries", "OnExitHold")
}

// TestRetryExpressionKeepsTernaryGrouping: `||` binds looser than every
// operator but the ternary, so only a ternary needs parentheses when it is
// joined on. Adding them anywhere else would regroup the expression.
func TestRetryExpressionKeepsTernaryGrouping(t *testing.T) {
	tern := cronRetryAd(t, "executable = /bin/sleep\nmax_retries = 1\nretry_until = ExitCode > 0 ? true : false\n")
	wantAttrs(t, tern, map[string]string{
		"OnExitRemove": "(((NumJobCompletions > JobMaxRetries) || (ExitCode is 0)) || ((ExitCode > 0) ? true : false))",
	})

	or := cronRetryAd(t, "executable = /bin/sleep\nmax_retries = 3\nretry_until = ExitCode == 7 || ExitCode == 8\n")
	wantAttrs(t, or, map[string]string{
		"OnExitRemove": "((((NumJobCompletions > JobMaxRetries) || (ExitCode is 0)) || (ExitCode == 7)) || (ExitCode == 8))",
	})
}

// TestSuccessExitCodeEnablesRetries: success_exit_code turns retries on by
// itself, and the generated expression compares against the attribute rather
// than baking the number in.
func TestSuccessExitCodeEnablesRetries(t *testing.T) {
	get := cronRetryAd(t, "executable = /bin/sleep\nsuccess_exit_code = 5\n")
	wantAttrs(t, get, map[string]string{
		"JobSuccessExitCode": "5",
		"JobMaxRetries":      "2",
		"OnExitRemove":       "((NumJobCompletions > JobMaxRetries) || (ExitCode is JobSuccessExitCode))",
	})
}

// TestMaxRetriesEvaluatesItsValue: condor_submit evaluates the value rather
// than scanning a number off its front, so `2+3` is five, not two.
func TestMaxRetriesEvaluatesItsValue(t *testing.T) {
	get := cronRetryAd(t, "executable = /bin/sleep\nmax_retries = 2+3\n")
	wantAttrs(t, get, map[string]string{"JobMaxRetries": "5"})
}

// TestSubmitterSetOnExitRemoveStands: an OnExitRemove set directly with
// +Attr or MY.Attr is left alone unless success_exit_code or retry_until
// asked for a change -- but JobMaxRetries and OnExitHold are still written.
func TestSubmitterSetOnExitRemoveStands(t *testing.T) {
	get := cronRetryAd(t, "executable = /bin/sleep\nMY.OnExitRemove = ExitCode == 9\nmax_retries = 3\n")
	wantAttrs(t, get, map[string]string{
		"OnExitRemove":  "(ExitCode == 9)",
		"JobMaxRetries": "3",
		"OnExitHold":    "false",
	})

	// retry_until is a change, so the expression is rebuilt.
	changed := cronRetryAd(t, "executable = /bin/sleep\nMY.OnExitRemove = ExitCode == 9\nmax_retries = 3\nretry_until = 42\n")
	wantAttrs(t, changed, map[string]string{
		"OnExitRemove": "(((NumJobCompletions > JobMaxRetries) || (ExitCode is 0)) || (ExitCode is 42))",
	})
}

// TestRetryAlternateSpellings: the submit commands have alternate spellings
// that are the attribute names themselves.
func TestRetryAlternateSpellings(t *testing.T) {
	get := cronRetryAd(t, "executable = /bin/sleep\nJobMaxRetries = 4\nOnExitRemove = ExitCode == 9\nOnExitHold = ExitCode == 3\n")
	wantAttrs(t, get, map[string]string{
		"JobMaxRetries": "4",
		"OnExitHold":    "(ExitCode == 3)",
		"OnExitRemove":  "(((NumJobCompletions > JobMaxRetries) || (ExitCode is 0)) || (ExitCode == 9))",
	})
}

// TestRetriesRejectInvalidValues: condor_submit fails the file rather than
// silently dropping a value it cannot use.
func TestRetriesRejectInvalidValues(t *testing.T) {
	for _, submit := range []string{
		"executable = /bin/sleep\nmax_retries = abc\n",
		"executable = /bin/sleep\nretry_until = 2147483648\n",
		"executable = /bin/sleep\nsuccess_exit_code = 2147483647\n",
	} {
		sf, err := ParseSubmitFile(strings.NewReader(submit))
		if err != nil {
			t.Fatalf("parse %q: %v", submit, err)
		}
		if _, err := sf.MakeJobAd(JobID{Cluster: 1, Proc: 0}, map[string]string{}); err == nil {
			t.Errorf("%q was accepted; condor_submit rejects it", submit)
		}
	}
}
