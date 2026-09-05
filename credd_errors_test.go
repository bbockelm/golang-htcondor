package htcondor

import (
	"strings"
	"testing"
)

// "query credential failed with code 12" was the whole diagnosis
// available for a credential stored as a placeholder string. 12 is
// FAILURE_JSON_PARSE in HTCondor's store_cred.h, which is not somewhere
// a caller -- or a model reading a tool result -- is going to look.
func TestCreddCodeMeaningExplainsJSONParse(t *testing.T) {
	got := creddCodeMeaning(FailureJSONParse)

	for _, want := range []string{"not valid JSON", "access_token"} {
		if !strings.Contains(got, want) {
			t.Errorf("the explanation is missing %q:\n%s", want, got)
		}
	}
	// It has to say what to do, not only what happened.
	if !strings.Contains(got, "Store a JSON document") {
		t.Errorf("the explanation gives no remedy:\n%s", got)
	}
	// And why the two read paths disagreed, which is the confusing part.
	if !strings.Contains(got, "store time") {
		t.Errorf("does not explain why the store succeeded:\n%s", got)
	}
}

func TestCreddErrorNamesTheOperationAndCode(t *testing.T) {
	err := creddError("query credential failed", FailureJSONParse)
	msg := err.Error()

	if !strings.Contains(msg, "query credential failed") {
		t.Errorf("operation missing: %s", msg)
	}
	// The number stays, because it is what a log or an HTCondor
	// developer will be searching for.
	if !strings.Contains(msg, "12") {
		t.Errorf("raw code missing: %s", msg)
	}
	if !strings.Contains(msg, "not valid JSON") {
		t.Errorf("meaning missing: %s", msg)
	}
}

// Every code HTCondor defines gets a real sentence; an unrecognized one
// still produces something rather than an empty string.
func TestCreddCodeMeaningCoversTheDefinedCodes(t *testing.T) {
	for _, code := range []int64{
		FailureBadPassword, FailureNoImpersonate, FailureNotSecure,
		FailureNotFound, FailureNotAllowed, FailureBadArgs,
		FailureProtocolMismatch, FailureCredmonTimeout, FailureConfigError,
		FailureJSONParse, FailureCredMismatch, FailureUntrustedHost,
	} {
		got := creddCodeMeaning(code)
		if got == "" || strings.Contains(got, "unrecognized") {
			t.Errorf("code %d has no explanation: %q", code, got)
		}
	}
	if got := creddCodeMeaning(9999); !strings.Contains(got, "unrecognized") {
		t.Errorf("an unknown code should say so, got %q", got)
	}
}

// The store path used to treat every failure code as success. A store
// refused by the credd was reported to the caller as having worked.
func TestStoreReturnValueClassification(t *testing.T) {
	// Mirrors the condition in storeCredential. Kept as a table so the
	// codes that must NOT be success are named explicitly.
	isSuccess := func(returnVal int64) bool {
		return returnVal == Success || returnVal == SuccessPending || returnVal > 100
	}

	for _, code := range []int64{Success, SuccessPending, 1700000000} {
		if !isSuccess(code) {
			t.Errorf("code %d should be success", code)
		}
	}
	for _, code := range []int64{
		Failure, FailureBadPassword, FailureNoImpersonate, FailureNotSecure,
		FailureNotAllowed, FailureBadArgs, FailureProtocolMismatch,
		FailureCredmonTimeout, FailureConfigError, FailureJSONParse,
		FailureCredMismatch, FailureUntrustedHost,
	} {
		if isSuccess(code) {
			t.Errorf("code %d (%s) must NOT be reported as a successful store",
				code, creddCodeMeaning(code))
		}
	}
	// The old condition, for the record: it let all of the above pass.
	oldIsSuccess := func(returnVal int64) bool {
		return !(returnVal < 0 || (returnVal > 20 && returnVal < 100))
	}
	if !oldIsSuccess(FailureJSONParse) {
		t.Error("fixture wrong: the old condition did accept code 12 as success")
	}
}
