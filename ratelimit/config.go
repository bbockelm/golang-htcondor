package ratelimit

import (
	"strconv"

	"github.com/bbockelm/golang-htcondor/config"
)

// ConfigFromHTCondor creates a rate limiter manager from HTCondor configuration
// Returns a manager with rate limits based on HTCondor configuration parameters:
//   - SCHEDD_QUERY_RATE_LIMIT: global rate limit for schedd queries (requests/sec)
//   - SCHEDD_QUERY_PER_USER_RATE_LIMIT: per-user rate limit for schedd queries (requests/sec)
//   - COLLECTOR_QUERY_RATE_LIMIT: global rate limit for collector queries (requests/sec)
//   - COLLECTOR_QUERY_PER_USER_RATE_LIMIT: per-user rate limit for collector queries (requests/sec)
//
// A value of 0 or unset means unlimited for that limit type.
func ConfigFromHTCondor(cfg *config.Config) *Manager {
	scheddGlobal := getFloatParam(cfg, "SCHEDD_QUERY_RATE_LIMIT", 0)
	scheddPerUser := getFloatParam(cfg, "SCHEDD_QUERY_PER_USER_RATE_LIMIT", 0)
	collectorGlobal := getFloatParam(cfg, "COLLECTOR_QUERY_RATE_LIMIT", 0)
	collectorPerUser := getFloatParam(cfg, "COLLECTOR_QUERY_PER_USER_RATE_LIMIT", 0)

	return NewManager(scheddGlobal, scheddPerUser, collectorGlobal, collectorPerUser)
}

// getFloatParam retrieves a float configuration parameter
// Returns defaultValue if the parameter is not set or cannot be parsed
func getFloatParam(cfg *config.Config, key string, defaultValue float64) float64 {
	if cfg == nil {
		return defaultValue
	}

	value, ok := cfg.Get(key)
	if !ok {
		return defaultValue
	}

	floatValue, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return defaultValue
	}

	// Negative values are treated as unlimited (0)
	if floatValue < 0 {
		return 0
	}

	return floatValue
}
