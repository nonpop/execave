package e2e_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestE2E_Config_ConfigLocation_DefaultConfigLocation tests that execave reads ./execave.json by default.
func TestE2E_Config_ConfigLocation_DefaultConfigLocation(t *testing.T) {
	failIfNoBwrap(t)

	workDir := testTempDir(t)
	writeConfigInDir(t, workDir, systemPaths())

	result := runExecave(t, workDir, "--", "echo", "hi")

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hi")
}

// TestE2E_Config_ConfigLocation_CustomConfigLocation tests that --config specifies a custom config path.
func TestE2E_Config_ConfigLocation_CustomConfigLocation(t *testing.T) {
	failIfNoBwrap(t)

	configPath := writeConfig(t, systemPaths())

	result := runExecave(t, "", "--config", configPath, "--", "echo", "hi")

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "hi")
}

// TestE2E_Config_ConfigValidation_ConfigFileNotFound tests that a missing config file produces an error.
func TestE2E_Config_ConfigValidation_ConfigFileNotFound(t *testing.T) {
	result := runExecave(t, "", "--config", "/nonexistent/config.json", "--", "echo", "hi")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "config file not found")
}

// TestE2E_Config_ConfigValidation_ValidConfig tests that a valid config runs the sandboxed command successfully.
func TestE2E_Config_ConfigValidation_ValidConfig(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	rules := append(systemPaths(),
		"fs:rw:"+tmpDir,
		"fs:none:/etc/shadow",
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 0)
}

// TestE2E_Config_ConfigValidation_EmptyRulesArray tests that empty rules array results in default-deny.
func TestE2E_Config_ConfigValidation_EmptyRulesArray(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoStrace(t)

	tmpDir := testTempDir(t)
	configPath := writeConfig(t, systemPaths())
	logPath := filepath.Join(tmpDir, "access.log")

	// With no rule for /etc/passwd, attempting to read it should fail
	result := runExecave(t, "", "--config", configPath, "--monitor="+logPath, "--", "cat", "/etc/passwd")

	// Should fail due to denied access (exit code from cat when it can't read)
	assert.NotEqual(t, 0, result.ExitCode)

	// Log should contain denial due to no matching rule
	assertLogLineContainsAll(t, logPath, "READ", "/etc/passwd", "no-matching-rule")
}

// TestE2E_Config_ConfigValidation_UnknownResourceType tests that unknown resource types produce an error.
func TestE2E_Config_ConfigValidation_UnknownResourceType(t *testing.T) {
	configPath := writeConfig(t, []string{"net:allow:443"})

	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "unknown resource type")
}
