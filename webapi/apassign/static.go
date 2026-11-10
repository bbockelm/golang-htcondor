package apassign

import (
	"context"
	"strings"
)

// Static assigns everyone to one schedd. A single-AP server is this
// backend with its one schedd; in multi-AP mode it assigns everyone to
// HTTP_API_AP_ASSIGNMENT_DEFAULT, and with no default it has no answer.
//
// It answers for everyone, so nothing after it in a chain would ever be
// asked; NewChain refuses a chain with anything after it.
type Static struct {
	Schedd string
}

// Assign implements Assigner.
func (s *Static) Assign(_ context.Context, _ Request) (Assignment, error) {
	name := strings.TrimSpace(s.Schedd)
	if name == "" {
		return Assignment{}, ErrNoAnswer
	}
	return Assignment{Schedd: name}, nil
}
