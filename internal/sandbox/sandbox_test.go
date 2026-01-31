package sandbox_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fsRule(permission config.Permission, path string) config.Rule {
	var permStr string
	switch permission {
	case config.PermissionReadOnly:
		permStr = "ro"
	case config.PermissionReadWrite:
		permStr = "rw"
	case config.PermissionNone:
		permStr = "none"
	case config.PermissionUnknown:
		permStr = "unknown"
	default:
		permStr = "unknown"
	}

	return config.Rule{
		Resource:   config.ResourceFS,
		Permission: permission,
		Path:       path,
		RawRule:    "fs:" + permStr + ":" + path,
	}
}

func TestBuildBwrapArgs(t *testing.T) {
	cfg := &config.Config{
		Rules: []config.Rule{
			fsRule(config.PermissionReadOnly, "/usr/bin"),
		},
	}

	sb := sandbox.New(cfg, "/tmp/execave-test.json")
	args := sb.BuildBwrapArgs([]string{"echo", "hello"})

	// Verify essential arguments
	assert.Contains(t, args, "--unshare-all")
	assert.Contains(t, args, "--dev")
	assert.Contains(t, args, "--proc")

	// Verify command is present
	hasCommand := false
	for i, a := range args {
		if a == "echo" && i+1 < len(args) && args[i+1] == "hello" {
			hasCommand = true
			break
		}
	}
	assert.True(t, hasCommand)
}

// argsContainSequence checks whether args contains the given sequence as consecutive elements.
func argsContainSequence(args []string, seq ...string) bool {
	for i := range len(args) - len(seq) + 1 {
		match := true
		for j, s := range seq {
			if args[i+j] != s {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestBuildBwrapArgs_NoneDirectoryWithoutChildren_Chmod0000(t *testing.T) {
	dir := t.TempDir()
	noneDir := filepath.Join(dir, "blocked")
	require.NoError(t, os.Mkdir(noneDir, 0o750))

	cfg := &config.Config{
		Rules: []config.Rule{
			fsRule(config.PermissionReadOnly, dir),
			fsRule(config.PermissionNone, noneDir),
		},
	}

	sb := sandbox.New(cfg, "")
	args := sb.BuildBwrapArgs([]string{"true"})

	assert.True(t, argsContainSequence(args, "--tmpfs", noneDir),
		"expected --tmpfs %s in args: %v", noneDir, args)
	assert.True(t, argsContainSequence(args, "--chmod", "0000", noneDir),
		"expected --chmod 0000 %s in args: %v", noneDir, args)
}

func TestBuildBwrapArgs_NoneDirectoryWithChildRule_Chmod0111(t *testing.T) {
	dir := t.TempDir()
	noneDir := filepath.Join(dir, "parent")
	childDir := filepath.Join(noneDir, "child")
	require.NoError(t, os.MkdirAll(childDir, 0o750))

	cfg := &config.Config{
		Rules: []config.Rule{
			fsRule(config.PermissionReadOnly, dir),
			fsRule(config.PermissionNone, noneDir),
			fsRule(config.PermissionReadWrite, childDir),
		},
	}

	sb := sandbox.New(cfg, "")
	args := sb.BuildBwrapArgs([]string{"true"})

	assert.True(t, argsContainSequence(args, "--tmpfs", noneDir),
		"expected --tmpfs %s in args: %v", noneDir, args)
	assert.True(t, argsContainSequence(args, "--chmod", "0111", noneDir),
		"expected --chmod 0111 %s in args: %v", noneDir, args)
}

func TestBuildBwrapArgs_NoneFile_NoChmod(t *testing.T) {
	dir := t.TempDir()
	noneFile := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(noneFile, []byte("secret"), 0o600))

	cfg := &config.Config{
		Rules: []config.Rule{
			fsRule(config.PermissionReadWrite, dir),
			fsRule(config.PermissionNone, noneFile),
		},
	}

	sb := sandbox.New(cfg, "")
	args := sb.BuildBwrapArgs([]string{"true"})

	// File should use /dev/null bind, not tmpfs
	assert.True(t, argsContainSequence(args, "--bind", "/dev/null", noneFile),
		"expected --bind /dev/null %s in args: %v", noneFile, args)
	// No --chmod should be present for the file
	assert.False(t, argsContainSequence(args, "--chmod", "0000", noneFile),
		"unexpected --chmod 0000 %s in args: %v", noneFile, args)
	assert.False(t, argsContainSequence(args, "--chmod", "0111", noneFile),
		"unexpected --chmod 0111 %s in args: %v", noneFile, args)
}
