package sandbox_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/binutil"
	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/nonpop/execave/internal/tunnel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fsRule(permission fsrules.Permission, path string) fsrules.Rule {
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

	return fsrules.Rule{
		Permission: permission,
		Path:       path,
		RawRule:    permStr + ":" + path,
		SourcePath: "",
	}
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

func resolveBwrap(t *testing.T) string {
	t.Helper()
	bwrapPath, err := binutil.ResolveBwrap()
	require.NoError(t, err)
	return bwrapPath
}

func TestBuildBwrapArgs(t *testing.T) {
	bwrapPath := resolveBwrap(t)

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}

	tunnelWrapped := tunnel.WrapCommand("/usr/local/bin/execave", "/tmp/proxy.sock", []string{"echo", "hello"})
	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, tunnelWrapped, 3)
	require.NoError(t, err)
	defer cleanup()
	args := sc.Args

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

func TestBuildBwrapArgs_NoneDirectoryWithoutChildren_Chmod0000(t *testing.T) {
	bwrapPath := resolveBwrap(t)

	dir := t.TempDir()
	noneDir := filepath.Join(dir, "blocked")
	require.NoError(t, os.Mkdir(noneDir, 0o750))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, dir),
			fsRule(fsrules.PermissionNone, noneDir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}

	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, []string{"true"}, 3)
	require.NoError(t, err)
	defer cleanup()
	args := sc.Args

	assert.True(t, argsContainSequence(args, "--tmpfs", noneDir))
	assert.True(t, argsContainSequence(args, "--chmod", "0000", noneDir))
}

func TestBuildBwrapArgs_NoneDirectoryWithChildRule_Chmod0111(t *testing.T) {
	bwrapPath := resolveBwrap(t)

	dir := t.TempDir()
	noneDir := filepath.Join(dir, "parent")
	childDir := filepath.Join(noneDir, "child")
	require.NoError(t, os.MkdirAll(childDir, 0o750))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, dir),
			fsRule(fsrules.PermissionNone, noneDir),
			fsRule(fsrules.PermissionReadWrite, childDir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}

	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, []string{"true"}, 3)
	require.NoError(t, err)
	defer cleanup()
	args := sc.Args

	assert.True(t, argsContainSequence(args, "--tmpfs", noneDir))
	assert.True(t, argsContainSequence(args, "--chmod", "0111", noneDir))
}

func TestBuildBwrapArgs_NoneFile_NoChmod(t *testing.T) {
	bwrapPath := resolveBwrap(t)

	dir := t.TempDir()
	noneFile := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(noneFile, []byte("secret"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadWrite, dir),
			fsRule(fsrules.PermissionNone, noneFile),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}

	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, []string{"true"}, 3)
	require.NoError(t, err)
	defer cleanup()
	args := sc.Args

	// File should use /dev/null bind, not tmpfs
	assert.True(t, argsContainSequence(args, "--bind", "/dev/null", noneFile))
	// No --chmod should be present for the file
	assert.False(t, argsContainSequence(args, "--chmod", "0000", noneFile))
	assert.False(t, argsContainSequence(args, "--chmod", "0111", noneFile))
}

func TestBuildBwrapArgs_NoShareNet(t *testing.T) {
	bwrapPath := resolveBwrap(t)

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{fsRule(fsrules.PermissionReadOnly, "/usr/bin")},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}

	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, []string{"true"}, 3)
	require.NoError(t, err)
	defer cleanup()
	args := sc.Args

	assert.Contains(t, args, "--unshare-all")
	assert.NotContains(t, args, "--share-net")
}

func TestBuildBwrapArgs_WithNetworkPath(t *testing.T) {
	bwrapPath := resolveBwrap(t)

	tmpDir := t.TempDir()
	udsFile := filepath.Join(tmpDir, "proxy.sock")
	require.NoError(t, os.WriteFile(udsFile, nil, 0o600))
	execaveFile := filepath.Join(tmpDir, "execave")
	require.NoError(t, os.WriteFile(execaveFile, nil, 0o755)) //nolint:gosec // test binary needs execute permission

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
			fsRule(fsrules.PermissionReadOnly, udsFile),
			fsRule(fsrules.PermissionReadOnly, execaveFile),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}

	tunnelWrapped := tunnel.WrapCommand(execaveFile, udsFile, []string{"echo", "hello"})
	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, tunnelWrapped, 3)
	require.NoError(t, err)
	defer cleanup()
	args := sc.Args

	// Should bind-mount UDS and execave binary at their host paths (same source/dest)
	assert.True(t, argsContainSequence(args, "--ro-bind", udsFile, udsFile))
	assert.True(t, argsContainSequence(args, "--ro-bind", execaveFile, execaveFile))

	// Command should be wrapped with tunnel using host paths
	assert.True(t, argsContainSequence(args, "--", execaveFile, "network-tunnel", udsFile, "--", "echo", "hello"))
}

func TestPrepare_SetupExecves3(t *testing.T) {
	bwrapPath := resolveBwrap(t)

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{fsRule(fsrules.PermissionReadOnly, "/usr/bin")},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,
		ConfigPaths:  nil,
	}
	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, []string{"true"}, 3)
	require.NoError(t, err)
	defer cleanup()

	assert.Equal(t, 3, sc.SetupExecves)
}

func TestPrepare_InsertsSeccompAtFD(t *testing.T) {
	bwrapPath := resolveBwrap(t)

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{fsRule(fsrules.PermissionReadOnly, "/usr/bin")},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,
		ConfigPaths:  nil,
	}
	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, []string{"true"}, 3)
	require.NoError(t, err)
	defer cleanup()

	assert.True(t, argsContainSequence(sc.Args, "--seccomp", "3", "--"))
	assert.NotEmpty(t, sc.ExtraFiles)
}

func TestPrepare_DoesNotModifyOriginalArgs(t *testing.T) {
	bwrapPath := resolveBwrap(t)

	cfg := &config.Config{
		FSRules:      []fsrules.Rule{fsRule(fsrules.PermissionReadOnly, "/usr/bin")},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,
		ConfigPaths:  nil,
	}
	command := []string{"true"}
	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, command, 3)
	require.NoError(t, err)
	defer cleanup()

	assert.Equal(t, []string{"true"}, command)
	assert.True(t, argsContainSequence(sc.Args, "--seccomp", "3"))
}

func TestManagedDirs(t *testing.T) {
	paths := sandbox.ManagedDirs()

	assert.Equal(t, []string{"/dev", "/proc", "/tmp", "/newroot", "/oldroot"}, paths)
}

func TestBuildBwrapArgs_IncludesInterpreterFromFSRules(t *testing.T) {
	bwrapPath := resolveBwrap(t)

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
			fsRule(fsrules.PermissionReadOnly, "/lib64/ld-linux-x86-64.so.2"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,
		ConfigPaths:  nil,
	}

	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, []string{"true"}, 3)
	require.NoError(t, err)
	defer cleanup()
	args := sc.Args

	assert.True(t, argsContainSequence(args, "--ro-bind", "/lib64/ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2"))
}

func TestBuildBwrapArgs_NoInterpreterWhenNotInFSRules(t *testing.T) {
	bwrapPath := resolveBwrap(t)

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,
		ConfigPaths:  nil,
	}

	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, []string{"true"}, 3)
	require.NoError(t, err)
	defer cleanup()
	args := sc.Args

	// No interpreter-related --ro-bind should appear (other than /usr/bin)
	for i, a := range args {
		if a == "--ro-bind" && i+1 < len(args) {
			assert.NotContains(t, args[i+1], "ld-linux")
		}
	}
}
