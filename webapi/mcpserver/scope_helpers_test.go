package mcpserver

// okScope adapts scopeToOwner's (constraint, error) result to the
// (constraint, ok) form these tests were written against: ok is false for
// any refusal, unauthenticated or malformed.
func okScope(constraint string, err error) (string, bool) {
	return constraint, err == nil
}
