package droppriv

import (
	"context"
	"errors"
	"fmt"
)

// ChainedLookupStrategy tries multiple strategies in order until one succeeds.
type ChainedLookupStrategy struct {
	strategies []LookupStrategy
}

// LookupUser tries each strategy in order until one succeeds or a user is definitively not found.
func (c *ChainedLookupStrategy) LookupUser(ctx context.Context, username string) (*UserInfo, error) {
	var lastErr error

	for _, strategy := range c.strategies {
		info, err := strategy.LookupUser(ctx, username)
		if err == nil {
			return info, nil
		}

		// If the error is "user not found", try the next strategy
		var notFoundErr *ErrUserNotFound
		if errors.As(err, &notFoundErr) {
			lastErr = err
			continue
		}

		// For other errors, continue to try next strategy but remember the error
		lastErr = err
	}

	// If we exhausted all strategies, return the last error
	if lastErr != nil {
		return nil, lastErr
	}

	// Should not reach here, but if we do, return user not found
	return nil, &ErrUserNotFound{Username: username}
}

// Name returns the names of all strategies in the chain.
func (c *ChainedLookupStrategy) Name() string {
	if len(c.strategies) == 0 {
		return "chained-empty"
	}

	name := "chained:"
	for i, s := range c.strategies {
		if i > 0 {
			name += ","
		}
		name += s.Name()
	}
	return name
}

// ErrStrategyNotAvailable is returned when a strategy is not available on the system.
var ErrStrategyNotAvailable = fmt.Errorf("strategy not available")
