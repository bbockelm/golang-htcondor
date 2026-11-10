package httpserver

import (
	"crypto/rand"
	"crypto/rsa"

	"golang.org/x/crypto/bcrypt"
)

// Startup work a daemon does once and this package's tests do for every
// server they build -- over a thousand times a run. Each is a variable
// so the package's TestMain can put a cheaper equivalent in its place
// (see main_test.go). Nothing outside the package can reach them, and
// nothing in the package assigns them.

// secretHashCost is the bcrypt cost for client secrets and IdP
// passwords.
var secretHashCost = bcrypt.DefaultCost

// generateSigningKey makes the RSA key an OAuth2 or IdP provider signs
// with, when its database does not hold one yet.
var generateSigningKey = func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// seedAppDB, when set, is called with the application database's path
// before the database is opened and migrated.
var seedAppDB func(path string)
