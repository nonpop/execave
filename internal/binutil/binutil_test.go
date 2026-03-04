package binutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterpreterPath_DynamicBinary(t *testing.T) {
	// Use /usr/bin/ls as a well-known dynamically linked binary.
	path, err := exec.LookPath("ls")
	require.NoError(t, err)

	interp := InterpreterPath(path)

	assert.NotEmpty(t, interp)
	assert.True(t, filepath.IsAbs(interp))
	assert.Contains(t, interp, "ld-linux")
}

func TestInterpreterPath_StaticBinary(t *testing.T) {
	// Build a static Go binary (CGO_ENABLED=0 produces static binaries).
	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "static")
	src := filepath.Join(tmpDir, "main.go")
	require.NoError(t, os.WriteFile(src, []byte("package main\nfunc main() {}\n"), 0o600))

	cmd := exec.Command("go", "build", "-o", binPath, src) // #nosec G204 -- binPath and src are constructed from t.TempDir()
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	t.Log(string(out))
	require.NoError(t, err)

	interp := InterpreterPath(binPath)

	assert.Empty(t, interp)
}

func TestInterpreterPath_NonexistentPath(t *testing.T) {
	interp := InterpreterPath("/nonexistent/binary")

	assert.Empty(t, interp)
}
