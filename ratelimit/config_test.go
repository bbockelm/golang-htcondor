package ratelimit

import (
	"testing"

	"github.com/bbockelm/golang-htcondor/config"
)

func TestConfigFromHTCondor(t *testing.T) {
	tests := []struct {
		name                     string
		configValues             map[string]string
		expectedScheddGlobal     float64
		expectedScheddPerUser    float64
		expectedCollectorGlobal  float64
		expectedCollectorPerUser float64
	}{
		{
			name:                     "empty config",
			configValues:             map[string]string{},
			expectedScheddGlobal:     0,
			expectedScheddPerUser:    0,
			expectedCollectorGlobal:  0,
			expectedCollectorPerUser: 0,
		},
		{
			name: "all limits set",
			configValues: map[string]string{
				"SCHEDD_QUERY_RATE_LIMIT":             "10",
				"SCHEDD_QUERY_PER_USER_RATE_LIMIT":    "5",
				"COLLECTOR_QUERY_RATE_LIMIT":          "20",
				"COLLECTOR_QUERY_PER_USER_RATE_LIMIT": "10",
			},
			expectedScheddGlobal:     10,
			expectedScheddPerUser:    5,
			expectedCollectorGlobal:  20,
			expectedCollectorPerUser: 10,
		},
		{
			name: "partial config",
			configValues: map[string]string{
				"SCHEDD_QUERY_RATE_LIMIT":             "15",
				"COLLECTOR_QUERY_PER_USER_RATE_LIMIT": "8",
			},
			expectedScheddGlobal:     15,
			expectedScheddPerUser:    0,
			expectedCollectorGlobal:  0,
			expectedCollectorPerUser: 8,
		},
		{
			name: "negative values treated as unlimited",
			configValues: map[string]string{
				"SCHEDD_QUERY_RATE_LIMIT":          "-1",
				"SCHEDD_QUERY_PER_USER_RATE_LIMIT": "-5",
			},
			expectedScheddGlobal:     0,
			expectedScheddPerUser:    0,
			expectedCollectorGlobal:  0,
			expectedCollectorPerUser: 0,
		},
		{
			name: "invalid values use defaults",
			configValues: map[string]string{
				"SCHEDD_QUERY_RATE_LIMIT":          "invalid",
				"SCHEDD_QUERY_PER_USER_RATE_LIMIT": "not_a_number",
			},
			expectedScheddGlobal:     0,
			expectedScheddPerUser:    0,
			expectedCollectorGlobal:  0,
			expectedCollectorPerUser: 0,
		},
		{
			name: "decimal values",
			configValues: map[string]string{
				"SCHEDD_QUERY_RATE_LIMIT":          "10.5",
				"SCHEDD_QUERY_PER_USER_RATE_LIMIT": "2.5",
			},
			expectedScheddGlobal:     10.5,
			expectedScheddPerUser:    2.5,
			expectedCollectorGlobal:  0,
			expectedCollectorPerUser: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.NewEmpty()
			for key, value := range tt.configValues {
				cfg.Set(key, value)
			}

			manager := ConfigFromHTCondor(cfg)

			scheddStats := manager.GetScheddStats()
			if scheddStats.GlobalRate != tt.expectedScheddGlobal {
				t.Errorf("schedd global rate: expected %f, got %f",
					tt.expectedScheddGlobal, scheddStats.GlobalRate)
			}
			if scheddStats.PerUserRate != tt.expectedScheddPerUser {
				t.Errorf("schedd per-user rate: expected %f, got %f",
					tt.expectedScheddPerUser, scheddStats.PerUserRate)
			}

			collectorStats := manager.GetCollectorStats()
			if collectorStats.GlobalRate != tt.expectedCollectorGlobal {
				t.Errorf("collector global rate: expected %f, got %f",
					tt.expectedCollectorGlobal, collectorStats.GlobalRate)
			}
			if collectorStats.PerUserRate != tt.expectedCollectorPerUser {
				t.Errorf("collector per-user rate: expected %f, got %f",
					tt.expectedCollectorPerUser, collectorStats.PerUserRate)
			}
		})
	}
}

func TestConfigFromHTCondorNilConfig(t *testing.T) {
	// Should not panic with nil config
	manager := ConfigFromHTCondor(nil)

	scheddStats := manager.GetScheddStats()
	if scheddStats.GlobalRate != 0 {
		t.Errorf("expected 0 global rate with nil config, got %f", scheddStats.GlobalRate)
	}

	collectorStats := manager.GetCollectorStats()
	if collectorStats.GlobalRate != 0 {
		t.Errorf("expected 0 global rate with nil config, got %f", collectorStats.GlobalRate)
	}
}

func TestGetFloatParam(t *testing.T) {
	cfg := config.NewEmpty()
	cfg.Set("VALID_INT", "42")
	cfg.Set("VALID_FLOAT", "3.14")
	cfg.Set("INVALID", "not_a_number")
	cfg.Set("NEGATIVE", "-10")
	cfg.Set("ZERO", "0")

	tests := []struct {
		name         string
		key          string
		defaultValue float64
		expected     float64
	}{
		{
			name:         "valid integer",
			key:          "VALID_INT",
			defaultValue: 0,
			expected:     42,
		},
		{
			name:         "valid float",
			key:          "VALID_FLOAT",
			defaultValue: 0,
			expected:     3.14,
		},
		{
			name:         "invalid value uses default",
			key:          "INVALID",
			defaultValue: 99,
			expected:     99,
		},
		{
			name:         "missing key uses default",
			key:          "MISSING",
			defaultValue: 123,
			expected:     123,
		},
		{
			name:         "negative treated as unlimited",
			key:          "NEGATIVE",
			defaultValue: 5,
			expected:     0,
		},
		{
			name:         "zero value",
			key:          "ZERO",
			defaultValue: 10,
			expected:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getFloatParam(cfg, tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("expected %f, got %f", tt.expected, result)
			}
		})
	}
}
