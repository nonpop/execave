package e2e_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_ConfiguringExecave_DefaultConfigLocation tests that execave reads ./execave.toml
// from the current working directory by default.
func TestE2E_ConfiguringExecave_DefaultConfigLocation(t *testing.T) {
	s := newScenario(t)
	workDir := s.givenDir("work")

	s.givenRulesInDir(workDir.String())

	s.whenRunWithDefaultConfig(workDir.String(), "echo", "hello")

	s.thenExitCode(0)
	s.thenStdoutContains("hello")
}

// TestE2E_ConfiguringExecave_CustomConfigPathViaConfig tests that --config overrides
// the default config location.
func TestE2E_ConfiguringExecave_CustomConfigPathViaConfig(t *testing.T) {
	s := newScenario(t)

	s.givenRules()

	s.whenRun("echo", "hello")

	s.thenExitCode(0)
	s.thenStdoutContains("hello")
}

// TestE2E_ConfiguringExecave_MissingConfigFileShowsError tests that a missing config file
// produces a clear error message.
func TestE2E_ConfiguringExecave_MissingConfigFileShowsError(t *testing.T) {
	result := runExecave(t, "", "--config", "/nonexistent/config.toml", "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "config file not found")
}

// TestE2E_ConfiguringExecave_InvalidRuleSyntaxRejectedBeforeExecution tests that a malformed
// rule is rejected at config load time and the command never executes.
func TestE2E_ConfiguringExecave_InvalidRuleSyntaxRejectedBeforeExecution(t *testing.T) {
	s := newScenario(t)
	s.givenRulesOnly("fs:readonly:/home/user")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("invalid permission type")
}

// TestE2E_ConfiguringExecave_UnknownResourceTypeRejected tests that rules with unrecognized
// resource prefixes are rejected before command execution.
func TestE2E_ConfiguringExecave_UnknownResourceTypeRejected(t *testing.T) {
	s := newScenario(t)
	s.givenRulesOnly("dns:allow:example.com")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("unknown resource type")
}

// TestE2E_ConfiguringExecave_DuplicateFilesystemPathsRejected tests that two rules targeting
// the same normalized path are rejected.
func TestE2E_ConfiguringExecave_DuplicateFilesystemPathsRejected(t *testing.T) {
	s := newScenario(t)
	s.givenRulesOnly("fs:ro:/home/user", "fs:rw:/home/user")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("duplicate path")
	s.thenStderrContains("/home/user")
}

// TestE2E_ConfiguringExecave_DuplicateNetworkRuleIdentityRejected tests that two net rules
// with the same target and port but different actions are rejected.
func TestE2E_ConfiguringExecave_DuplicateNetworkRuleIdentityRejected(t *testing.T) {
	s := newScenario(t)
	s.givenRules("net:http:example.com:443", "net:none:example.com:443")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("duplicate net rule")
}

// TestE2E_ConfiguringExecave_MixedPortPatternsOnSameTargetRejected tests that a wildcard port
// and a specific port on the same target are rejected.
func TestE2E_ConfiguringExecave_MixedPortPatternsOnSameTargetRejected(t *testing.T) {
	s := newScenario(t)
	s.givenRules("net:http:example.com:*", "net:none:example.com:443")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("mixed port patterns")
}

// TestE2E_ConfiguringExecave_ConfigFileExplicitlyWritableRejected tests that a rule granting
// rw access to the config file itself is rejected.
func TestE2E_ConfiguringExecave_ConfigFileExplicitlyWritableRejected(t *testing.T) {
	tmpDir := testTempDir(t)
	configPath := filepath.Join(tmpDir, "execave.toml")

	configContent := `rules = ["fs:rw:` + configPath + `"]`
	err := os.WriteFile(configPath, []byte(configContent), 0o600)
	require.NoError(t, err)

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "config file must not be writable")
}

// TestE2E_ConfiguringExecave_ManagedPathsInRulesRejected tests that rules targeting managed
// paths (/dev, /proc, /tmp) or their descendants are rejected.
func TestE2E_ConfiguringExecave_ManagedPathsInRulesRejected(t *testing.T) {
	s := newScenario(t)
	s.givenRulesOnly("fs:ro:/proc/self/status")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("managed path")
}

// TestE2E_ConfiguringExecave_TildeRuleExpandsAndMountsCorrectly tests that a tilde
// path in a rule is expanded to the home directory and the path is mounted correctly.
func TestE2E_ConfiguringExecave_TildeRuleExpandsAndMountsCorrectly(t *testing.T) {
	s := newScenario(t)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	data := s.givenDir("data")
	dataFile := data.file("data.txt", "tilde content")

	rel, err := filepath.Rel(homeDir, data.String())
	require.NoError(t, err)
	require.False(t, filepath.IsAbs(rel))

	tildeDir := "~/" + rel
	s.givenRules("fs:ro:" + tildeDir)

	s.whenRun("cat", dataFile)

	s.thenExitCode(0)
	s.thenStdoutContains("tilde content")
}

// TestE2E_ConfiguringExecave_TildeDuplicatePathRejected tests that two tilde rules
// that expand to the same absolute path are rejected with a duplicate path error.
func TestE2E_ConfiguringExecave_TildeDuplicatePathRejected(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	tmpDir := testTempDir(t)
	rel, err := filepath.Rel(homeDir, tmpDir)
	require.NoError(t, err)
	require.False(t, filepath.IsAbs(rel))

	tildeDir := "~/" + rel
	rules := []string{
		"fs:ro:" + tildeDir,
		"fs:rw:" + tmpDir,
	}

	result := runExecave(t, "", "--config", writeConfig(t, rules), "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "duplicate path")
	assert.Contains(t, result.Stderr, tmpDir)
}

// TestE2E_ConfiguringExecave_CommentsInConfig tests that TOML comments in the config
// file are ignored and the config loads successfully.
func TestE2E_ConfiguringExecave_CommentsInConfig(t *testing.T) {
	s := newScenario(t)
	s.givenRawConfig(`# Sandbox config
rules = [
    # System libraries
    "fs:ro:/usr",
    "fs:ro:/lib",
    "fs:ro:/lib64",
    "fs:ro:/etc/ld.so.cache",  # linker cache
]`)

	s.whenRun("echo", "hello")

	s.thenExitCode(0)
	s.thenStdoutContains("hello")
}
