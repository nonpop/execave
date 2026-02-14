package config_test

import (
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Config file location ---
// Note: "Default config location" and "Custom config location" test CLI flag routing,
// not the config package. config.Load always receives an explicit path from the caller.

func TestIntegration_ConfigFileLocation_ConfigFileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/config.json", nil)

	require.Error(t, err)
	assert.ErrorContains(t, err, "config file not found")
}

// --- Requirement: Config file format ---

func TestIntegration_ConfigFileFormat_ValidConfigWithFsAndNetRules(t *testing.T) {
	cfg, err := loadTestConfig(t, `{"rules": ["fs:ro:/usr/bin", "net:https:api.anthropic.com:443"]}`)

	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
	assert.Len(t, cfg.NetRules, 1)
}

func TestIntegration_ConfigFileFormat_EmptyRulesArray(t *testing.T) {
	cfg, err := loadTestConfig(t, `{"rules": []}`)

	require.NoError(t, err)
	assert.Empty(t, cfg.FSRules)
	assert.Empty(t, cfg.NetRules)
}

func TestIntegration_ConfigFileFormat_UnknownResourceType(t *testing.T) {
	_, err := loadTestConfig(t, `{"rules": ["dns:allow:example.com"]}`)

	assert.ErrorContains(t, err, "unknown resource type")
}

func TestIntegration_ConfigFileFormat_InvalidRuleRejectedAtConfigLoad(t *testing.T) {
	_, err := loadTestConfig(t, `{"rules": ["net:https:example.com"]}`)

	assert.ErrorContains(t, err, "malformed rule")
}
