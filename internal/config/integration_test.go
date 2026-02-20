package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Config file location ---
// Note: "Default config location" and "Custom config location" test CLI flag routing,
// not the config package. config.Load always receives an explicit path from the caller.

func TestIntegration_ConfigFileLocation_ConfigFileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/config.toml", nil)

	require.Error(t, err)
	assert.ErrorContains(t, err, "config file not found")
}

// --- Requirement: Config file format ---

func TestIntegration_ConfigFileFormat_ValidConfigWithFsAndNetRules(t *testing.T) {
	cfg, err := loadTestConfig(t, `rules = ["fs:ro:/usr/bin", "net:https:api.anthropic.com:443"]`)

	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
	assert.Len(t, cfg.NetRules, 1)
}

func TestIntegration_ConfigFileFormat_EmptyRulesArray(t *testing.T) {
	cfg, err := loadTestConfig(t, `rules = []`)

	require.NoError(t, err)
	assert.Empty(t, cfg.FSRules)
	assert.Empty(t, cfg.NetRules)
}

func TestIntegration_ConfigFileFormat_UnknownResourceType(t *testing.T) {
	_, err := loadTestConfig(t, `rules = ["dns:allow:example.com"]`)

	assert.ErrorContains(t, err, "unknown resource type")
}

func TestIntegration_ConfigFileFormat_InvalidRuleRejectedAtConfigLoad(t *testing.T) {
	_, err := loadTestConfig(t, `rules = ["net:https:example.com"]`)

	assert.ErrorContains(t, err, "malformed rule")
}

func TestIntegration_ConfigFileFormat_ConfigWithComments(t *testing.T) {
	content := `# Sandbox for my coding agent
rules = [
    # Project directory: read-only
    "fs:ro:/usr/bin",  # inline comment
    "net:https:api.anthropic.com:443",
]`

	cfg, err := loadTestConfig(t, content)

	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
	assert.Len(t, cfg.NetRules, 1)
}

func TestIntegration_ConfigFileFormat_ConfigWithTrailingComma(t *testing.T) {
	cfg, err := loadTestConfig(t, `rules = ["fs:ro:/usr/bin",]`)

	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
}

// --- Requirement: Parse rules from in-memory strings ---

func TestIntegration_ParseRules_ValidFsAndNetRules(t *testing.T) {
	cfg, err := config.ParseRules(
		[]string{"fs:ro:/usr/bin", "net:https:api.example.com:443"},
		"/some/dir", "/some/dir/execave.toml", nil,
	)

	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
	assert.Len(t, cfg.NetRules, 1)
}

func TestIntegration_ParseRules_EmptyRulesProduceEmptyConfig(t *testing.T) {
	cfg, err := config.ParseRules([]string{}, "/some/dir", "/some/dir/execave.toml", nil)

	require.NoError(t, err)
	assert.Empty(t, cfg.FSRules)
	assert.Empty(t, cfg.NetRules)
}

func TestIntegration_ParseRules_InvalidRuleRejected(t *testing.T) {
	_, err := config.ParseRules(
		[]string{"badprefix:something"},
		"/some/dir", "/some/dir/execave.toml", nil,
	)

	assert.ErrorContains(t, err, "unknown resource type")
}

func TestIntegration_ParseRules_DuplicatePathsRejected(t *testing.T) {
	_, err := config.ParseRules(
		[]string{"fs:ro:/usr/bin", "fs:rw:/usr/bin"},
		"/some/dir", "/some/dir/execave.toml", nil,
	)

	assert.ErrorContains(t, err, "duplicate path")
}

func TestIntegration_ParseRules_ManagedPathRejected(t *testing.T) {
	_, err := config.ParseRules(
		[]string{"fs:ro:/dev"},
		"/some/dir", "/some/dir/execave.toml", []string{"/dev"},
	)

	assert.ErrorContains(t, err, "managed path")
}

func TestIntegration_ParseRules_ConfigWritabilityRejected(t *testing.T) {
	_, err := config.ParseRules(
		[]string{"fs:rw:/home/user/execave.toml"},
		"/home/user", "/home/user/execave.toml", nil,
	)

	assert.ErrorContains(t, err, "config file must not be writable")
}

func TestIntegration_ParseRules_NonAbsoluteConfigPathPanics(t *testing.T) {
	assert.Panics(t, func() {
		_, _ = config.ParseRules([]string{}, "/some/dir", "relative/execave.toml", nil)
	})
}

// --- Requirement: ParseTOML ---

func TestIntegration_ParseTOML_ProducesIdenticalConfigToLoad(t *testing.T) {
	content := `rules = ["fs:ro:/usr/bin", "net:https:api.example.com:443"]`
	managedPaths := []string{"/proc", "/dev"}

	configPath := writeTestConfig(t, content)
	loadedCfg, err := config.Load(configPath, managedPaths)
	require.NoError(t, err)

	rawContent, err := os.ReadFile(configPath) // #nosec G304 -- configPath is a known temp path from writeTestConfig
	require.NoError(t, err)
	parsedCfg, err := config.ParseTOML(rawContent, filepath.Dir(configPath), configPath, managedPaths)
	require.NoError(t, err)

	require.Len(t, parsedCfg.FSRules, len(loadedCfg.FSRules))
	require.Len(t, parsedCfg.NetRules, len(loadedCfg.NetRules))
	assert.Equal(t, loadedCfg.FSRules[0].Path, parsedCfg.FSRules[0].Path)
	assert.Equal(t, loadedCfg.FSRules[0].Permission, parsedCfg.FSRules[0].Permission)
	assert.Equal(t, loadedCfg.FSRules[0].RawRule, parsedCfg.FSRules[0].RawRule)
	assert.Equal(t, loadedCfg.ManagedPaths, parsedCfg.ManagedPaths)
}

// --- Requirement: Load delegates to ParseRules ---

func TestIntegration_ParseRules_LoadAndParseRulesProduceIdenticalConfig(t *testing.T) {
	rawRules := []string{"fs:ro:/usr/bin", "net:https:api.example.com:443"}
	managedPaths := []string{"/proc", "/dev"}

	// Write the same rules to a TOML file and Load it
	configPath := writeTestConfig(t, `rules = ["fs:ro:/usr/bin", "net:https:api.example.com:443"]`)
	loadedCfg, err := config.Load(configPath, managedPaths)
	require.NoError(t, err)

	// Parse the same rule strings directly
	parsedCfg, err := config.ParseRules(rawRules, filepath.Dir(configPath), configPath, managedPaths)
	require.NoError(t, err)

	// Both should produce equivalent configs
	require.Len(t, parsedCfg.FSRules, len(loadedCfg.FSRules))
	require.Len(t, parsedCfg.NetRules, len(loadedCfg.NetRules))
	assert.Equal(t, loadedCfg.FSRules[0].Path, parsedCfg.FSRules[0].Path)
	assert.Equal(t, loadedCfg.FSRules[0].Permission, parsedCfg.FSRules[0].Permission)
	assert.Equal(t, loadedCfg.FSRules[0].RawRule, parsedCfg.FSRules[0].RawRule)
	assert.Equal(t, loadedCfg.ManagedPaths, parsedCfg.ManagedPaths)
}
