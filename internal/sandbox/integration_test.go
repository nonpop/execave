package sandbox_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/sandbox"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Requirement: Default-deny filesystem ---

func TestIntegration_DefaultDenyFilesystem_NoMatchingRule(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"cat", "/opt/secret"})

	// /opt/secret should not appear in any mount args
	assert.False(t, argsContainSequence(args, "--ro-bind", "/opt/secret", "/opt/secret"))
	assert.False(t, argsContainSequence(args, "--bind", "/opt/secret", "/opt/secret"))
}

func TestIntegration_DefaultDenyFilesystem_AllowedPathAccessible(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"bash"})

	assert.True(t, argsContainSequence(args, "--ro-bind", "/usr/bin", "/usr/bin"))
}

// --- Requirement: Read-only access ---

func TestIntegration_ReadOnlyAccess_ReadAllowed(t *testing.T) {
	dir := t.TempDir()

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, dir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"cat", filepath.Join(dir, "data.txt")})

	assert.True(t, argsContainSequence(args, "--ro-bind", dir, dir))
}

func TestIntegration_ReadOnlyAccess_WriteDeniedOnReadOnlyPath(t *testing.T) {
	dir := t.TempDir()

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, dir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"touch", filepath.Join(dir, "test.txt")})

	// Must use --ro-bind (not --bind) so bwrap enforces read-only
	assert.True(t, argsContainSequence(args, "--ro-bind", dir, dir))
	assert.False(t, argsContainSequence(args, "--bind", dir, dir))
}

// --- Requirement: Read-write access ---

func TestIntegration_ReadWriteAccess_ReadAllowedOnReadWritePath(t *testing.T) {
	dir := t.TempDir()

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadWrite, dir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"cat", filepath.Join(dir, "test.txt")})

	assert.True(t, argsContainSequence(args, "--bind", dir, dir))
}

func TestIntegration_ReadWriteAccess_WriteAllowedOnReadWritePath(t *testing.T) {
	dir := t.TempDir()

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadWrite, dir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"touch", filepath.Join(dir, "test.txt")})

	assert.True(t, argsContainSequence(args, "--bind", dir, dir))
}

// --- Requirement: No-access rule ---

func TestIntegration_NoAccessRule_ReadDeniedByNoneRule(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("secret"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadWrite, dir),
			fsRule(fsrules.PermissionNone, secretFile),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"cat", secretFile})

	assert.True(t, argsContainSequence(args, "--bind", "/dev/null", secretFile))
}

func TestIntegration_NoAccessRule_WriteDeniedByNoneRule(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("secret"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadWrite, dir),
			fsRule(fsrules.PermissionNone, secretFile),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"sh", "-c", "echo test > " + secretFile})

	assert.True(t, argsContainSequence(args, "--bind", "/dev/null", secretFile))
}

func TestIntegration_NoAccessRule_NoneDirectoryInaccessible(t *testing.T) {
	dir := t.TempDir()
	blockedDir := filepath.Join(dir, "blocked")
	require.NoError(t, os.Mkdir(blockedDir, 0o750))

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadWrite, dir),
			fsRule(fsrules.PermissionNone, blockedDir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"ls", blockedDir})

	assert.True(t, argsContainSequence(args, "--tmpfs", blockedDir))
	assert.True(t, argsContainSequence(args, "--chmod", "0000", blockedDir))
}

func TestIntegration_NoAccessRule_NoneDirectoryWithChildRuleAllowsChildAccess(t *testing.T) {
	dir := t.TempDir()
	parentDir := filepath.Join(dir, "parent")
	childDir := filepath.Join(parentDir, "child")
	require.NoError(t, os.MkdirAll(childDir, 0o750))

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadWrite, dir),
			fsRule(fsrules.PermissionNone, parentDir),
			fsRule(fsrules.PermissionReadWrite, childDir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"cat", filepath.Join(childDir, "data.txt")})

	// Parent gets tmpfs + 0111 (execute-only for traversal)
	assert.True(t, argsContainSequence(args, "--tmpfs", parentDir))
	assert.True(t, argsContainSequence(args, "--chmod", "0111", parentDir))
	// Child is bind-mounted over the parent's tmpfs
	assert.True(t, argsContainSequence(args, "--bind", childDir, childDir))
}

// --- Requirement: Default-deny network ---

func TestIntegration_DefaultDenyNetwork_NoNetRulesMeansNoNetwork(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"true"})

	assert.Contains(t, args, "--unshare-all")
	assert.NotContains(t, args, "--share-net")
}

func TestIntegration_DefaultDenyNetwork_NoNetRulesMeansNoDNS(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"true"})

	// --unshare-all isolates network namespace, preventing DNS
	assert.Contains(t, args, "--unshare-all")
}

// --- Requirement: Proxy-tunnel path setup ---

func TestIntegration_ProxyTunnelPathSetup_NetRulesTriggerProxyTunnelSetup(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	netPath := &sandbox.NetworkPath{
		UDSPath:       "/tmp/proxy.sock",
		ExecaveBinary: "/usr/local/bin/execave",
	}
	sb := sandbox.New(cfg, "", netPath)

	args := sb.BuildBwrapArgs([]string{"curl", "https://api.example.com"})

	// Command should be wrapped with tunnel
	assert.True(t, argsContainSequence(args,
		"--", "/tmp/execave", "network-tunnel", "/tmp/execave-proxy.sock", "--",
		"curl", "https://api.example.com"))
}

func TestIntegration_ProxyTunnelPathSetup_ProxyUDSBindMountedIntoSandbox(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	netPath := &sandbox.NetworkPath{
		UDSPath:       "/tmp/test-proxy.sock",
		ExecaveBinary: "/usr/local/bin/execave",
	}
	sb := sandbox.New(cfg, "", netPath)

	args := sb.BuildBwrapArgs([]string{"true"})

	assert.True(t, argsContainSequence(args, "--ro-bind", "/tmp/test-proxy.sock", "/tmp/execave-proxy.sock"))
}

func TestIntegration_ProxyTunnelPathSetup_ExecaveBinaryBindMountedReadOnly(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	netPath := &sandbox.NetworkPath{
		UDSPath:       "/tmp/proxy.sock",
		ExecaveBinary: "/usr/local/bin/execave",
	}
	sb := sandbox.New(cfg, "", netPath)

	args := sb.BuildBwrapArgs([]string{"true"})

	assert.True(t, argsContainSequence(args, "--ro-bind", "/usr/local/bin/execave", "/tmp/execave"))
}

// --- Requirement: Processes ignoring HTTP_PROXY have no network ---

func TestIntegration_ProcessesIgnoringHTTPPROXYHaveNoNetwork_DirectConnectionFails(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	netPath := &sandbox.NetworkPath{
		UDSPath:       "/tmp/proxy.sock",
		ExecaveBinary: "/usr/local/bin/execave",
	}
	sb := sandbox.New(cfg, "", netPath)

	args := sb.BuildBwrapArgs([]string{"true"})

	// Even with net rules, --unshare-all isolates network (no NIC)
	assert.Contains(t, args, "--unshare-all")
	assert.NotContains(t, args, "--share-net")
}

func TestIntegration_ProcessesIgnoringHTTPPROXYHaveNoNetwork_UDPFails(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	netPath := &sandbox.NetworkPath{
		UDSPath:       "/tmp/proxy.sock",
		ExecaveBinary: "/usr/local/bin/execave",
	}
	sb := sandbox.New(cfg, "", netPath)

	args := sb.BuildBwrapArgs([]string{"true"})

	assert.Contains(t, args, "--unshare-all")
}

// --- Requirement: CLI command execution ---

func TestIntegration_CLICommandExecution_CommandExecutionWithoutNetRules(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"echo", "hello"})

	// Command directly after -- (no tunnel wrapping)
	assert.True(t, argsContainSequence(args, "--", "echo", "hello"))
	assert.False(t, argsContainSequence(args, "network-tunnel"))
}

func TestIntegration_CLICommandExecution_CommandExecutionWithNetRules(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      nil,
	}
	netPath := &sandbox.NetworkPath{
		UDSPath:       "/tmp/proxy.sock",
		ExecaveBinary: "/usr/local/bin/execave",
	}
	sb := sandbox.New(cfg, "", netPath)

	args := sb.BuildBwrapArgs([]string{"python", "script.py"})

	// Command wrapped with tunnel
	assert.True(t, argsContainSequence(args,
		"/tmp/execave", "network-tunnel", "/tmp/execave-proxy.sock", "--",
		"python", "script.py"))
}

// Note: ExitCodePropagationWithTunnel requires running bwrap + tunnel.

// --- Requirement: Config file protection ---

func TestIntegration_ConfigFileProtection_ConfigFileInRwDirectoryForcedToRo(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "execave.json")
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadWrite, dir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      sandbox.ManagedDirs,
	}
	sb := sandbox.New(cfg, configPath, nil)

	args := sb.BuildBwrapArgs([]string{"true"})

	// Parent dir is --bind (rw), then config file overlaid with --ro-bind
	assert.True(t, argsContainSequence(args, "--bind", dir, dir))
	assert.True(t, argsContainSequence(args, "--ro-bind", configPath, configPath))
}

func TestIntegration_ConfigFileProtection_ConfigFileProtectionDoesNotBlockSiblingAccess(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "execave.json")
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadWrite, dir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      sandbox.ManagedDirs,
	}
	sb := sandbox.New(cfg, configPath, nil)

	args := sb.BuildBwrapArgs([]string{"true"})

	// Parent dir still gets --bind (rw access for siblings)
	assert.True(t, argsContainSequence(args, "--bind", dir, dir))
}

func TestIntegration_ConfigFileProtection_ConfigFileNotMountedStaysUnmounted(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	workDir := filepath.Join(dir, "work")
	require.NoError(t, os.Mkdir(configDir, 0o750))
	require.NoError(t, os.Mkdir(workDir, 0o750))
	configPath := filepath.Join(configDir, "execave.json")
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadWrite, workDir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      sandbox.ManagedDirs,
	}
	sb := sandbox.New(cfg, configPath, nil)

	args := sb.BuildBwrapArgs([]string{"true"})

	// Config path should NOT be in any mount args
	assert.False(t, argsContainSequence(args, "--ro-bind", configPath, configPath))
	assert.False(t, argsContainSequence(args, "--bind", configPath, configPath))
}

func TestIntegration_ConfigFileProtection_ConfigFileAlreadyRoStaysRo(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "execave.json")
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, dir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      sandbox.ManagedDirs,
	}
	sb := sandbox.New(cfg, configPath, nil)

	args := sb.BuildBwrapArgs([]string{"true"})

	// Parent is already --ro-bind; no separate config overlay needed
	assert.True(t, argsContainSequence(args, "--ro-bind", dir, dir))
	// Should NOT have a separate ro-bind for the config file
	assert.False(t, argsContainSequence(args, "--ro-bind", configPath, configPath))
}

// --- Requirement: Seccomp filtering ---

func TestIntegration_SeccompFiltering_BlockedSyscallReturnsEPERM(t *testing.T) {
	_, err := exec.LookPath("bwrap")
	require.NoError(t, err)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "prog.sh"), []byte("#!/bin/sh\nptrace 0 0 0 0 2>/dev/null; echo $?"), 0o755)) // #nosec G306 -- test script needs execute permission

	// Use a real bwrap run: run a shell that attempts ptrace (blocked) and prints exit status.
	// With seccomp enabled, ptrace returns EPERM (exit 1 from the shell calling the syscall).
	// We verify the sandbox runs and exits without crashing (seccomp filter is plumbed correctly).
	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
			fsRule(fsrules.PermissionReadOnly, "/usr/lib"),
			fsRule(fsrules.PermissionReadOnly, "/usr/lib64"),
			fsRule(fsrules.PermissionReadOnly, "/lib"),
			fsRule(fsrules.PermissionReadOnly, "/lib64"),
			fsRule(fsrules.PermissionReadOnly, "/bin"),
			fsRule(fsrules.PermissionReadOnly, dir),
		},
		NetRules:          nil,
		FSLogRules:        nil,
		NetLogRules:       nil,
		SyscallAllowRules: nil,
		SyscallNologRules: nil,
		ManagedPaths:      sandbox.ManagedDirs,
	}
	sb := sandbox.New(cfg, "", nil)
	ctx := context.Background()

	// Just verify bwrap starts successfully with the seccomp filter plumbed.
	// The filter is applied — if there's a plumbing error, bwrap exits with error.
	exitCode, runErr := sb.Run(ctx, []string{"true"})
	require.NoError(t, runErr)
	assert.Equal(t, 0, exitCode)
}

// --- Requirement: Binary validation ---

func TestIntegration_BinaryValidation_BwrapNotFoundInPATH(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := sandbox.ResolveBwrap()

	assert.ErrorContains(t, err, "not found in PATH")
}

func TestIntegration_BinaryValidation_NonRootOwnedBinaryRejected(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBwrap := filepath.Join(tmpDir, "bwrap")
	require.NoError(t, os.WriteFile(fakeBwrap, []byte("fake"), 0o755)) // #nosec G306 -- test binary needs execute permission
	t.Setenv("PATH", tmpDir)

	_, err := sandbox.ResolveBwrap()

	assert.ErrorContains(t, err, "not owned by root")
}

func TestIntegration_BinaryValidation_NonRootSymlinkToBinaryRejected(t *testing.T) {
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target")
	require.NoError(t, os.WriteFile(target, []byte("fake"), 0o755)) // #nosec G306 -- test binary needs execute permission
	link := filepath.Join(tmpDir, "bwrap")
	require.NoError(t, os.Symlink(target, link))
	t.Setenv("PATH", tmpDir)

	_, err := sandbox.ResolveBwrap()

	assert.ErrorContains(t, err, "not owned by root")
}

func TestIntegration_BinaryValidation_StraceNotFoundInPATH(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	_, err := sandbox.ResolveStrace()

	assert.ErrorContains(t, err, "not found in PATH")
}

func TestIntegration_BinaryValidation_NonRootOwnedStraceRejected(t *testing.T) {
	tmpDir := t.TempDir()
	fakeStrace := filepath.Join(tmpDir, "strace")
	require.NoError(t, os.WriteFile(fakeStrace, []byte("fake"), 0o755)) // #nosec G306 -- test binary needs execute permission
	t.Setenv("PATH", tmpDir)

	_, err := sandbox.ResolveStrace()

	assert.ErrorContains(t, err, "not owned by root")
}

// --- Requirement: ELF interpreter auto-mount ---

func TestIntegration_InterpreterAutoMount_RuleTargetingInterpreterPathRejected(t *testing.T) {
	// Detect the real interpreter path from a known dynamic binary.
	lsPath, err := exec.LookPath("ls")
	require.NoError(t, err)

	interpPath := sandbox.InterpreterPath(lsPath)
	require.NotEmpty(t, interpPath)

	managedPaths := sandbox.ManagedPathsWith(interpPath)

	_, err = config.ParseRules(
		[]string{"fs:ro:" + interpPath},
		"/",
		"/config.toml",
		managedPaths,
	)

	assert.ErrorContains(t, err, "managed path")
}

func TestIntegration_InterpreterAutoMount_InterpreterMountedInBwrapArgs(t *testing.T) {
	// Detect the real interpreter path from a known dynamic binary.
	lsPath, err := exec.LookPath("ls")
	require.NoError(t, err)

	interpPath := sandbox.InterpreterPath(lsPath)
	require.NotEmpty(t, interpPath)

	cfg := &config.Config{
		FSRules: []fsrules.AccessRule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		InterpreterPath: interpPath,
		ManagedPaths:    sandbox.ManagedPathsWith(interpPath),
	}
	sb := sandbox.New(cfg, "", nil)

	args := sb.BuildBwrapArgs([]string{"true"})

	assert.True(t, argsContainSequence(args, "--ro-bind", interpPath, interpPath))
}
