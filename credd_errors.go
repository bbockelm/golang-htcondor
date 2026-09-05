package htcondor

import "fmt"

// Return codes the credd sends back from a store or query, from
// HTCondor's store_cred.h. The ones this package already names (Success,
// FailureNotFound, ...) are declared in credd_client.go; these fill in
// the rest so an error can say what happened instead of quoting a
// number.
const (
	// FailureNoImpersonate means user switching is not supported.
	FailureNoImpersonate = 3
	// FailureProtocolMismatch means client and server disagreed about
	// what should have been sent on the wire.
	FailureProtocolMismatch = 9
	// FailureCredmonTimeout means the credmon did not process the
	// credential within its timeout.
	FailureCredmonTimeout = 10
	// FailureJSONParse means the stored credential could not be parsed
	// as JSON. An OAuth service credential is a JSON document, and the
	// credd re-parses it when a query names a specific service -- so a
	// credential stored as something else is written without complaint
	// and then fails every read of it thereafter.
	FailureJSONParse = 12
	// FailureCredMismatch means a credential was found but did not match
	// the requested scopes or audience.
	FailureCredMismatch = 13
	// FailureUntrustedHost means the credential would require contacting
	// a host the credd does not trust.
	FailureUntrustedHost = 14
)

// creddCodeMeaning explains a credd return code. The text is aimed at
// whoever has to act on it -- an operator reading a log, or a model
// deciding what to do next -- so it says what went wrong and, where
// there is one, what to do about it.
//
// "query credential failed with code 12" was the entire diagnosis
// available for a credential that had been stored as a placeholder
// string: the number is in HTCondor's store_cred.h and nowhere a caller
// would look.
func creddCodeMeaning(code int64) string {
	switch code {
	case FailureBadPassword:
		return "the password was rejected"
	case FailureNoImpersonate:
		return "the credd cannot switch users, so it cannot act for this user"
	case FailureNotSecure:
		return "the connection was not secure enough to carry a credential"
	case FailureNotFound:
		return "no such credential"
	case FailureNotAllowed:
		return "the authenticated user is not allowed to do this"
	case FailureBadArgs:
		return "the request was missing an argument, or its arguments contradicted each other"
	case FailureProtocolMismatch:
		return "client and server disagree about the protocol; they may be different versions"
	case FailureCredmonTimeout:
		return "the credential monitor did not process the credential in time"
	case FailureConfigError:
		return "the credd is misconfigured"
	case FailureJSONParse:
		return "the stored credential is not valid JSON. An OAuth service credential must be a JSON " +
			"document (for example {\"access_token\":\"...\"}); the credd accepts anything at store time " +
			"but re-parses it when a query names a specific service, so a credential stored as a plain " +
			"string is written successfully and then fails every read of it. Store a JSON document to fix it"
	case FailureCredMismatch:
		return "a credential exists but does not match the requested scopes or audience"
	case FailureUntrustedHost:
		return "the credential would require contacting a host the credd does not trust"
	default:
		return "unrecognized credd status"
	}
}

// creddError builds an error for a non-success credd return code.
func creddError(op string, code int64) error {
	return fmt.Errorf("%s: %s (credd code %d)", op, creddCodeMeaning(code), code)
}
