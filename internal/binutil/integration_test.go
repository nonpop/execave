package binutil_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/binutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeVersionBinary creates a shell script that prints versionLine when invoked with --version.
// The script is not root-owned, so it can only be used with Check*Version directly, not ResolveBwrap/ResolveStrace.
func fakeVersionBinary(t *testing.T, name, versionLine string) string {
	t.Helper()
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, name)
	content := fmt.Sprintf("#!/bin/sh\necho '%s'\n", versionLine)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o755)) // #nosec G306 -- test script needs execute permission
	return p
}

// --- Requirement: Binary validation ---

func TestIntegration_BinaryValidation_BwrapNotFoundInPATH(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := binutil.ResolveBwrap()

	assert.ErrorContains(t, err, "look up path")
}

func TestIntegration_BinaryValidation_NonRootOwnedBinaryRejected(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBwrap := filepath.Join(tmpDir, "bwrap")
	require.NoError(t, os.WriteFile(fakeBwrap, []byte("fake"), 0o755)) // #nosec G306 -- test binary needs execute permission
	t.Setenv("PATH", tmpDir)

	_, err := binutil.ResolveBwrap()

	assert.ErrorContains(t, err, "not owned by root")
}

func TestIntegration_BinaryValidation_NonRootSymlinkToBinaryRejected(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target")
	require.NoError(t, os.WriteFile(target, []byte("fake"), 0o755)) // #nosec G306 -- test binary needs execute permission
	link := filepath.Join(tmpDir, "bwrap")
	require.NoError(t, os.Symlink(target, link))
	t.Setenv("PATH", tmpDir)

	_, err := binutil.ResolveBwrap()

	assert.ErrorContains(t, err, "not owned by root")
}

func TestIntegration_BinaryValidation_StraceNotFoundInPATH(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := binutil.ResolveStrace()

	assert.ErrorContains(t, err, "look up path")
}

func TestIntegration_BinaryValidation_NonRootOwnedStraceRejected(t *testing.T) {
	tmpDir := t.TempDir()
	fakeStrace := filepath.Join(tmpDir, "strace")
	require.NoError(t, os.WriteFile(fakeStrace, []byte("fake"), 0o755)) // #nosec G306 -- test binary needs execute permission
	t.Setenv("PATH", tmpDir)

	_, err := binutil.ResolveStrace()

	assert.ErrorContains(t, err, "not owned by root")
}

// --- Requirement: bwrap version check ---

func TestIntegration_BwrapVersionCheck_IncompatibleVersionReturnsError(t *testing.T) {
	fakeBwrap := fakeVersionBinary(t, "bwrap", "bwrap 0.10.0")

	_, err := binutil.CheckBwrapVersion(fakeBwrap)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "incompatible")
}

func TestIntegration_BwrapVersionCheck_WarnTierVersionPrintsWarningAndContinues(t *testing.T) {
	fakeBwrap := fakeVersionBinary(t, "bwrap", "bwrap 0.12.0")

	warn, err := binutil.CheckBwrapVersion(fakeBwrap)

	assert.NoError(t, err)
	assert.NotEmpty(t, warn)
}

// --- Requirement: strace version check ---

func TestIntegration_StraceVersionCheck_IncompatibleVersionReturnsError(t *testing.T) {
	fakeStrace := fakeVersionBinary(t, "strace", "strace -- version 6.18")

	_, err := binutil.CheckStraceVersion(fakeStrace)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "incompatible")
}

func TestIntegration_StraceVersionCheck_WarnTierVersionPrintsWarningAndContinues(t *testing.T) {
	fakeStrace := fakeVersionBinary(t, "strace", "strace -- version 6.20")

	warn, err := binutil.CheckStraceVersion(fakeStrace)

	assert.NoError(t, err)
	assert.NotEmpty(t, warn)
}

// TestIntegration_BwrapVersionCheck_MajorBumpReturnsError verifies that
// CheckBwrapVersion returns an error for a major-version bump (originally tested via runner).
func TestIntegration_BwrapVersionCheck_MajorBumpReturnsError(t *testing.T) {
	fakeBwrap := fakeVersionBinary(t, "bwrap", "bwrap 1.0.0")

	_, err := binutil.CheckBwrapVersion(fakeBwrap)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "incompatible")
}
