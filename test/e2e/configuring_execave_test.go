package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_ConfiguringExecave_DefaultConfigLocation tests that execave reads ./execave.json
// from the current working directory by default.
func TestE2E_ConfiguringExecave_DefaultConfigLocation(t *testing.T) {
	failIfNoBwrap(t)

	workDir := testTempDir(t)
	writeConfigInDir(t, workDir, systemPaths())

	result := runExecave(t, workDir, "--", "echo", "hello")

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hello")
}

// TestE2E_ConfiguringExecave_CustomConfigPathViaConfig tests that --config overrides
// the default config location.
func TestE2E_ConfiguringExecave_CustomConfigPathViaConfig(t *testing.T) {
	failIfNoBwrap(t)

	configPath := writeConfig(t, systemPaths())

	result := runExecave(t, "", "--config", configPath, "--", "echo", "hello")

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hello")
}

// TestE2E_ConfiguringExecave_MissingConfigFileShowsError tests that a missing config file
// produces a clear error message.
func TestE2E_ConfiguringExecave_MissingConfigFileShowsError(t *testing.T) {
	result := runExecave(t, "", "--config", "/nonexistent/config.json", "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "config file not found")
}

// TestE2E_ConfiguringExecave_InvalidRuleSyntaxRejectedBeforeExecution tests that a malformed
// rule is rejected at config load time and the command never executes.
func TestE2E_ConfiguringExecave_InvalidRuleSyntaxRejectedBeforeExecution(t *testing.T) {
	configPath := writeConfig(t, []string{"fs:readonly:/home/user"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "invalid permission type")
}

// TestE2E_ConfiguringExecave_UnknownResourceTypeRejected tests that rules with unrecognized
// resource prefixes are rejected before command execution.
func TestE2E_ConfiguringExecave_UnknownResourceTypeRejected(t *testing.T) {
	configPath := writeConfig(t, []string{"dns:allow:example.com"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "unknown resource type")
}

// TestE2E_ConfiguringExecave_DuplicateFilesystemPathsRejected tests that two rules targeting
// the same normalized path are rejected.
func TestE2E_ConfiguringExecave_DuplicateFilesystemPathsRejected(t *testing.T) {
	configPath := writeConfig(t, []string{"fs:ro:/home/user", "fs:rw:/home/user"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "duplicate path")
	assert.Contains(t, result.Stderr, "/home/user")
}

// TestE2E_ConfiguringExecave_DuplicateNetworkRuleIdentityRejected tests that two net rules
// with the same target and port but different actions are rejected.
func TestE2E_ConfiguringExecave_DuplicateNetworkRuleIdentityRejected(t *testing.T) {
	configPath := writeConfig(t, append(systemPaths(),
		"net:https:example.com:443",
		"net:none:example.com:443",
	))

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "duplicate net rule")
}

// TestE2E_ConfiguringExecave_MixedPortPatternsOnSameTargetRejected tests that a wildcard port
// and a specific port on the same target are rejected.
func TestE2E_ConfiguringExecave_MixedPortPatternsOnSameTargetRejected(t *testing.T) {
	configPath := writeConfig(t, append(systemPaths(),
		"net:https:example.com:*",
		"net:none:example.com:443",
	))

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "mixed port patterns")
}

// TestE2E_ConfiguringExecave_ConfigFileExplicitlyWritableRejected tests that a rule granting
// rw access to the config file itself is rejected.
func TestE2E_ConfiguringExecave_ConfigFileExplicitlyWritableRejected(t *testing.T) {
	tmpDir := testTempDir(t)
	configPath := filepath.Join(tmpDir, "execave.json")

	configContent := `{"rules": ["fs:rw:` + configPath + `"]}`
	err := os.WriteFile(configPath, []byte(configContent), 0o600)
	require.NoError(t, err)

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "config file must not be writable")
}

// TestE2E_ConfiguringExecave_ManagedPathsInRulesRejected tests that rules targeting managed
// paths (/dev, /proc, /tmp) or their descendants are rejected.
func TestE2E_ConfiguringExecave_ManagedPathsInRulesRejected(t *testing.T) {
	configPath := writeConfig(t, []string{"fs:ro:/proc/self/status"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "managed path")
}
