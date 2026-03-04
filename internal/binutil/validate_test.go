package binutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateBinary_nonexistentPath(t *testing.T) {
	err := validateBinary("/nonexistent/path/bwrap")
	assert.Error(t, err)
}

func TestValidateBinary_notOwnedByRoot(t *testing.T) {
	tmpDir := t.TempDir()
	bin := filepath.Join(tmpDir, "fakebinary")
	require.NoError(t, os.WriteFile(bin, []byte("fake"), 0o755)) // #nosec G306 -- test binary needs execute permission

	err := validateBinary(bin)
	assert.ErrorContains(t, err, "not owned by root")
}

func TestValidateBinary_symlinkNotOwnedByRoot(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target")
	require.NoError(t, os.WriteFile(target, []byte("fake"), 0o755)) // #nosec G306 -- test binary needs execute permission

	link := filepath.Join(tmpDir, "link")
	require.NoError(t, os.Symlink(target, link))

	// Both the symlink and target are owned by the current (non-root) user,
	// so validation fails on the symlink ownership check (Lstat).
	err := validateBinary(link)
	assert.ErrorContains(t, err, "not owned by root")
}

func TestResolveBwrap(t *testing.T) {
	path, err := ResolveBwrap()
	if err != nil {
		// bwrap not found or validation failed — both are expected in CI.
		// At minimum, verify the error references "bwrap".
		assert.ErrorContains(t, err, "bwrap")
	} else {
		assert.NotEmpty(t, path)
	}
}

func TestResolveStrace(t *testing.T) {
	path, err := ResolveStrace()
	if err != nil {
		// strace not found or validation failed — both are expected in CI.
		// At minimum, verify the error references "strace".
		assert.ErrorContains(t, err, "strace")
	} else {
		assert.NotEmpty(t, path)
	}
}
