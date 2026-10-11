package authz

import "strings"

// SameUser reports whether a and b name the same user: the user parts (up to
// the first '@') compared exactly and the domains case-insensitively, as
// HTCondor's is_same_user compares two fully-qualified users with
// COMPARE_DOMAIN_FULL (uids.cpp). A name without a domain matches only a name
// without one. HTCondor reports a peer's domain in lower case whatever case a
// configuration spells it in, so a list of identities compared with == misses
// an entry written "alice@Example.ORG".
func SameUser(a, b string) bool {
	userA, domainA, atA := strings.Cut(a, "@")
	userB, domainB, atB := strings.Cut(b, "@")
	return atA == atB && userA == userB && strings.EqualFold(domainA, domainB)
}
