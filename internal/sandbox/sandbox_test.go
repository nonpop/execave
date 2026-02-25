package sandbox_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fsRule(permission fsrules.Permission, path string) fsrules.AccessRule {
	var permStr string
	switch permission {
	case fsrules.PermissionReadOnly:
		permStr = "ro"
	case fsrules.PermissionReadWrite:
		permStr = "rw"
	case fsrules.PermissionNone:
		permStr = "none"
	case fsrules.PermissionUnknown:
		permStr = "unknown"
	default:
		permStr = "unknown"
	}

	return fsrules.AccessRule{
		Permission: permission,
		Path:       path,
		RawRule:    "fs:" + permStr + ":" + path,
	}
}

func TestBuildBwrapArgs(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		FSLogRules:   nil,
		NetLogRules:  nil,
		ManagedPaths: nil,
	}

	sb := sandbox.New(cfg, "/tmp/execave-test.json", nil)
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
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, dir),
			fsRule(fsrules.PermissionNone, noneDir),
		},
		NetRules:     nil,
		FSLogRules:   nil,
		NetLogRules:  nil,
		ManagedPaths: nil,
	}

	sb := sandbox.New(cfg, "", nil)
	args := sb.BuildBwrapArgs([]string{"true"})

	assert.True(t, argsContainSequence(args, "--tmpfs", noneDir))
	assert.True(t, argsContainSequence(args, "--chmod", "0000", noneDir))
}

func TestBuildBwrapArgs_NoneDirectoryWithChildRule_Chmod0111(t *testing.T) {
	dir := t.TempDir()
	noneDir := filepath.Join(dir, "parent")
	childDir := filepath.Join(noneDir, "child")
	require.NoError(t, os.MkdirAll(childDir, 0o750))

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, dir),
			fsRule(fsrules.PermissionNone, noneDir),
			fsRule(fsrules.PermissionReadWrite, childDir),
		},
		NetRules:     nil,
		FSLogRules:   nil,
		NetLogRules:  nil,
		ManagedPaths: nil,
	}

	sb := sandbox.New(cfg, "", nil)
	args := sb.BuildBwrapArgs([]string{"true"})

	assert.True(t, argsContainSequence(args, "--tmpfs", noneDir))
	assert.True(t, argsContainSequence(args, "--chmod", "0111", noneDir))
}

func TestBuildBwrapArgs_NoneFile_NoChmod(t *testing.T) {
	dir := t.TempDir()
	noneFile := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(noneFile, []byte("secret"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadWrite, dir),
			fsRule(fsrules.PermissionNone, noneFile),
		},
		NetRules:     nil,
		FSLogRules:   nil,
		NetLogRules:  nil,
		ManagedPaths: nil,
	}

	sb := sandbox.New(cfg, "", nil)
	args := sb.BuildBwrapArgs([]string{"true"})

	// File should use /dev/null bind, not tmpfs
	assert.True(t, argsContainSequence(args, "--bind", "/dev/null", noneFile))
	// No --chmod should be present for the file
	assert.False(t, argsContainSequence(args, "--chmod", "0000", noneFile))
	assert.False(t, argsContainSequence(args, "--chmod", "0111", noneFile))
}

func TestBuildBwrapArgs_NoShareNet(t *testing.T) {
	cfg := &config.Config{
		FSRules:      []fsrules.AccessRule{fsRule(fsrules.PermissionReadOnly, "/usr/bin")},
		NetRules:     nil,
		FSLogRules:   nil,
		NetLogRules:  nil,
		ManagedPaths: nil,
	}

	sb := sandbox.New(cfg, "", nil)
	args := sb.BuildBwrapArgs([]string{"true"})

	assert.Contains(t, args, "--unshare-all")
	assert.NotContains(t, args, "--share-net")
}

func TestBuildBwrapArgs_WithNetworkPath(t *testing.T) {
	cfg := &config.Config{
		FSRules:      []fsrules.AccessRule{fsRule(fsrules.PermissionReadOnly, "/usr/bin")},
		NetRules:     nil,
		FSLogRules:   nil,
		NetLogRules:  nil,
		ManagedPaths: nil,
	}

	netPath := &sandbox.NetworkPath{
		UDSPath:       "/tmp/test-proxy.sock",
		ExecaveBinary: "/usr/local/bin/execave",
	}

	sb := sandbox.New(cfg, "", netPath)
	args := sb.BuildBwrapArgs([]string{"echo", "hello"})

	// Should bind-mount UDS and execave binary
	assert.True(t, argsContainSequence(args, "--ro-bind", "/tmp/test-proxy.sock", "/tmp/execave-proxy.sock"))
	assert.True(t, argsContainSequence(args, "--ro-bind", "/usr/local/bin/execave", "/tmp/execave"))

	// Command should be wrapped with tunnel
	assert.True(t, argsContainSequence(args, "--", "/tmp/execave", "network-tunnel", "/tmp/execave-proxy.sock", "--", "echo", "hello"))
}

func TestBuildBwrapArgs_WithoutNetworkPath(t *testing.T) {
	cfg := &config.Config{
		FSRules:      []fsrules.AccessRule{fsRule(fsrules.PermissionReadOnly, "/usr/bin")},
		NetRules:     nil,
		FSLogRules:   nil,
		NetLogRules:  nil,
		ManagedPaths: nil,
	}

	sb := sandbox.New(cfg, "", nil)
	args := sb.BuildBwrapArgs([]string{"echo", "hello"})

	// Should not have tunnel wrapping
	assert.False(t, argsContainSequence(args, "network-tunnel"))
	// Command should follow -- directly
	assert.True(t, argsContainSequence(args, "--", "echo", "hello"))
}

func TestHasNetworkPath(t *testing.T) {
	cfg := new(config.Config)

	sb := sandbox.New(cfg, "", nil)
	assert.False(t, sb.HasNetworkPath())

	sb = sandbox.New(cfg, "", &sandbox.NetworkPath{
		UDSPath:       "/tmp/proxy.sock",
		ExecaveBinary: "/usr/bin/execave",
	})
	assert.True(t, sb.HasNetworkPath())
}
