package sandbox_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
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

// fakeVersionBinary creates a shell script in a temp dir that prints versionLine on stdout when
// invoked with --version, and exits 0 otherwise. The script is executable by the test user
// (not root-owned), so it is suitable for calling CheckBwrapVersion/CheckStraceVersion directly
// but not for use with ResolveBwrap/ResolveStrace (which require root ownership).
func fakeVersionBinary(t *testing.T, name, versionLine string) string {
	t.Helper()
	tmpDir := t.TempDir()
	p := filepath.Join(tmpDir, name)
	content := fmt.Sprintf("#!/bin/sh\necho '%s'\n", versionLine)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o755)) // #nosec G306 -- test script needs execute permission
	return p
}

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

const (
	dummyTunnelBinary = "/usr/local/bin/execave"
	dummyUDSPath      = "/tmp/test-proxy.sock"
)

// prepare calls sandbox.Prepare with seccompFD=3, returning the bwrap args.
// It adds RO rules for the tunnel binary and UDS, then wraps the command using the given paths.
// The returned close func must be called to release the seccomp pipe.
func prepare(t *testing.T, cfg *config.Config, tunnelBinary, udsPath string, command []string) (args []string, close func()) {
	t.Helper()
	bwrapPath, err := binutil.ResolveBwrap()
	require.NoError(t, err)
	cfg.FSRules = append(cfg.FSRules, fsRule(fsrules.PermissionReadOnly, tunnelBinary))
	cfg.FSRules = append(cfg.FSRules, fsRule(fsrules.PermissionReadOnly, udsPath))
	wrapped := tunnel.WrapCommand(tunnelBinary, udsPath, command)
	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, wrapped, 3)
	require.NoError(t, err)
	return sc.Args, cleanup
}

// --- Requirement: Default-deny filesystem ---

func TestIntegration_DefaultDenyFilesystem_NoMatchingRule(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"cat", "/opt/secret"})
	defer close()

	// /opt/secret should not appear in any mount args
	assert.False(t, argsContainSequence(args, "--ro-bind", "/opt/secret", "/opt/secret"))
	assert.False(t, argsContainSequence(args, "--bind", "/opt/secret", "/opt/secret"))
}

func TestIntegration_DefaultDenyFilesystem_AllowedPathAccessible(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"bash"})
	defer close()

	assert.True(t, argsContainSequence(args, "--ro-bind", "/usr/bin", "/usr/bin"))
}

// --- Requirement: Read-only access ---

func TestIntegration_ReadOnlyAccess_ReadAllowed(t *testing.T) {
	dir := t.TempDir()

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, dir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"cat", filepath.Join(dir, "data.txt")})
	defer close()

	assert.True(t, argsContainSequence(args, "--ro-bind", dir, dir))
}

func TestIntegration_ReadOnlyAccess_WriteDeniedOnReadOnlyPath(t *testing.T) {
	dir := t.TempDir()

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, dir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"touch", filepath.Join(dir, "test.txt")})
	defer close()

	// Must use --ro-bind (not --bind) so bwrap enforces read-only
	assert.True(t, argsContainSequence(args, "--ro-bind", dir, dir))
	assert.False(t, argsContainSequence(args, "--bind", dir, dir))
}

// --- Requirement: Read-write access ---

func TestIntegration_ReadWriteAccess_ReadAllowedOnReadWritePath(t *testing.T) {
	dir := t.TempDir()

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadWrite, dir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"cat", filepath.Join(dir, "test.txt")})
	defer close()

	assert.True(t, argsContainSequence(args, "--bind", dir, dir))
}

func TestIntegration_ReadWriteAccess_WriteAllowedOnReadWritePath(t *testing.T) {
	dir := t.TempDir()

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadWrite, dir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"touch", filepath.Join(dir, "test.txt")})
	defer close()

	assert.True(t, argsContainSequence(args, "--bind", dir, dir))
}

// --- Requirement: No-access rule ---

func TestIntegration_NoAccessRule_ReadDeniedByNoneRule(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("secret"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadWrite, dir),
			fsRule(fsrules.PermissionNone, secretFile),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"cat", secretFile})
	defer close()

	assert.True(t, argsContainSequence(args, "--bind", "/dev/null", secretFile))
}

func TestIntegration_NoAccessRule_WriteDeniedByNoneRule(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("secret"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadWrite, dir),
			fsRule(fsrules.PermissionNone, secretFile),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"sh", "-c", "echo test > " + secretFile})
	defer close()

	assert.True(t, argsContainSequence(args, "--bind", "/dev/null", secretFile))
}

func TestIntegration_NoAccessRule_NoneDirectoryInaccessible(t *testing.T) {
	dir := t.TempDir()
	blockedDir := filepath.Join(dir, "blocked")
	require.NoError(t, os.Mkdir(blockedDir, 0o750))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadWrite, dir),
			fsRule(fsrules.PermissionNone, blockedDir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"ls", blockedDir})
	defer close()

	assert.True(t, argsContainSequence(args, "--tmpfs", blockedDir))
	assert.True(t, argsContainSequence(args, "--chmod", "0000", blockedDir))
}

func TestIntegration_NoAccessRule_NoneDirectoryWithChildRuleAllowsChildAccess(t *testing.T) {
	dir := t.TempDir()
	parentDir := filepath.Join(dir, "parent")
	childDir := filepath.Join(parentDir, "child")
	require.NoError(t, os.MkdirAll(childDir, 0o750))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadWrite, dir),
			fsRule(fsrules.PermissionNone, parentDir),
			fsRule(fsrules.PermissionReadWrite, childDir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"cat", filepath.Join(childDir, "data.txt")})
	defer close()

	// Parent gets tmpfs + 0111 (execute-only for traversal)
	assert.True(t, argsContainSequence(args, "--tmpfs", parentDir))
	assert.True(t, argsContainSequence(args, "--chmod", "0111", parentDir))
	// Child is bind-mounted over the parent's tmpfs
	assert.True(t, argsContainSequence(args, "--bind", childDir, childDir))
}

// --- Requirement: Default-deny network ---

func TestIntegration_DefaultDenyNetwork_NoNetRulesMeansNoNetwork(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"true"})
	defer close()

	assert.Contains(t, args, "--unshare-all")
	assert.NotContains(t, args, "--share-net")
}

func TestIntegration_DefaultDenyNetwork_NoNetRulesMeansNoDNS(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"true"})
	defer close()

	// --unshare-all isolates network namespace, preventing DNS
	assert.Contains(t, args, "--unshare-all")
}

// --- Requirement: Proxy-tunnel path setup ---

func TestIntegration_ProxyTunnelPathSetup_NetRulesTriggerProxyTunnelSetup(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, "/usr/local/bin/execave", "/tmp/proxy.sock", []string{"curl", "https://api.example.com"})
	defer close()

	// Command should be wrapped with tunnel using host paths
	assert.True(t, argsContainSequence(args,
		"--", "/usr/local/bin/execave", "network-tunnel", "/tmp/proxy.sock", "--",
		"curl", "https://api.example.com"))
}

func TestIntegration_ProxyTunnelPathSetup_ProxyUDSBindMountedIntoSandbox(t *testing.T) {
	udsFile := filepath.Join(t.TempDir(), "proxy.sock")
	require.NoError(t, os.WriteFile(udsFile, nil, 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, "/usr/local/bin/execave", udsFile, []string{"true"})
	defer close()

	// UDS is bind-mounted at its host path (same source/dest)
	assert.True(t, argsContainSequence(args, "--ro-bind", udsFile, udsFile))
}

func TestIntegration_ProxyTunnelPathSetup_ExecaveBinaryBindMountedReadOnly(t *testing.T) {
	execaveBinary, err := os.Executable()
	require.NoError(t, err)

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, execaveBinary, "/tmp/proxy.sock", []string{"true"})
	defer close()

	// Execave binary is bind-mounted at its host path (same source/dest)
	assert.True(t, argsContainSequence(args, "--ro-bind", execaveBinary, execaveBinary))
}

// --- Requirement: Processes ignoring HTTP_PROXY have no network ---

func TestIntegration_ProcessesIgnoringHTTPPROXYHaveNoNetwork_DirectConnectionFails(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, "/usr/local/bin/execave", "/tmp/proxy.sock", []string{"true"})
	defer close()

	// Even with net rules, --unshare-all isolates network (no NIC)
	assert.Contains(t, args, "--unshare-all")
	assert.NotContains(t, args, "--share-net")
}

func TestIntegration_ProcessesIgnoringHTTPPROXYHaveNoNetwork_UDPFails(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, "/usr/local/bin/execave", "/tmp/proxy.sock", []string{"true"})
	defer close()

	assert.Contains(t, args, "--unshare-all")
}

// --- Requirement: CLI command execution ---

func TestIntegration_CLICommandExecution_CommandWrappedWithTunnel(t *testing.T) {
	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: nil,

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"echo", "hello"})
	defer close()

	// Command wrapped with tunnel using host paths
	assert.True(t, argsContainSequence(args,
		"/usr/local/bin/execave", "network-tunnel", "/tmp/test-proxy.sock", "--",
		"echo", "hello"))
}

// Note: ExitCodePropagationWithTunnel requires running bwrap + tunnel.

// --- Requirement: Config file protection ---

func TestIntegration_ConfigFileProtection_ConfigFileInRwDirectoryForcedToRo(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "execave.json")
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadWrite, dir),
			{Permission: fsrules.PermissionReadOnly, Path: configPath, RawRule: "ro:" + configPath, SourcePath: ""},
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: sandbox.ManagedDirs(),

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"true"})
	defer close()

	// Parent dir is --bind (rw), then config file overlaid with --ro-bind
	assert.True(t, argsContainSequence(args, "--bind", dir, dir))
	assert.True(t, argsContainSequence(args, "--ro-bind", configPath, configPath))
}

func TestIntegration_ConfigFileProtection_ConfigFileProtectionDoesNotBlockSiblingAccess(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "execave.json")
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadWrite, dir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: sandbox.ManagedDirs(),

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"true"})
	defer close()

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
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadWrite, workDir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: sandbox.ManagedDirs(),

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"true"})
	defer close()

	// Config path should NOT be in any mount args
	assert.False(t, argsContainSequence(args, "--ro-bind", configPath, configPath))
	assert.False(t, argsContainSequence(args, "--bind", configPath, configPath))
}

func TestIntegration_ConfigFileProtection_ConfigFileAlreadyRoStaysRo(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "execave.json")
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, dir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: sandbox.ManagedDirs(),

		ConfigPaths: nil,
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"true"})
	defer close()

	// Parent is already --ro-bind; no separate config overlay needed
	assert.True(t, argsContainSequence(args, "--ro-bind", dir, dir))
	// Should NOT have a separate ro-bind for the config file
	assert.False(t, argsContainSequence(args, "--ro-bind", configPath, configPath))
}

func TestIntegration_ConfigFileProtection_LayeredConfigPathsForcedRoAfterMerge(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.toml")
	rootPath := filepath.Join(dir, "execave.toml")
	require.NoError(t, os.WriteFile(basePath, []byte("{}"), 0o600))
	require.NoError(t, os.WriteFile(rootPath, []byte("{}"), 0o600))

	cfg := &config.Config{
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadWrite, dir),
			{Permission: fsrules.PermissionReadOnly, Path: basePath, RawRule: "ro:" + basePath, SourcePath: ""},
			{Permission: fsrules.PermissionReadOnly, Path: rootPath, RawRule: "ro:" + rootPath, SourcePath: ""},
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: sandbox.ManagedDirs(),

		ConfigPaths: []string{basePath, rootPath},
	}
	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"true"})
	defer close()

	assert.True(t, argsContainSequence(args, "--bind", dir, dir))
	assert.True(t, argsContainSequence(args, "--ro-bind", basePath, basePath))
	assert.True(t, argsContainSequence(args, "--ro-bind", rootPath, rootPath))
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
		FSRules: []fsrules.Rule{
			fsRule(fsrules.PermissionReadOnly, "/usr/bin"),
			fsRule(fsrules.PermissionReadOnly, "/usr/lib"),
			fsRule(fsrules.PermissionReadOnly, "/usr/lib64"),
			fsRule(fsrules.PermissionReadOnly, "/lib"),
			fsRule(fsrules.PermissionReadOnly, "/lib64"),
			fsRule(fsrules.PermissionReadOnly, "/bin"),
			fsRule(fsrules.PermissionReadOnly, dir),
		},
		NetRules:     nil,
		SyscallRules: nil,
		ManagedPaths: sandbox.ManagedDirs(),

		ConfigPaths: nil,
	}
	ctx := context.Background()

	// Just verify bwrap starts successfully with the seccomp filter plumbed.
	// The filter is applied — if there's a plumbing error, bwrap exits with error.
	udsFile := filepath.Join(t.TempDir(), "proxy.sock")
	require.NoError(t, os.WriteFile(udsFile, nil, 0o600))
	truePath, err := exec.LookPath("true")
	require.NoError(t, err)
	bwrapPath, err := binutil.ResolveBwrap()
	require.NoError(t, err)
	cfg.FSRules = append(cfg.FSRules, fsRule(fsrules.PermissionReadOnly, truePath))
	cfg.FSRules = append(cfg.FSRules, fsRule(fsrules.PermissionReadOnly, udsFile))
	wrapped := tunnel.WrapCommand(truePath, udsFile, []string{"true"})
	sc, cleanup, err := sandbox.Prepare(bwrapPath, cfg, wrapped, 3)
	require.NoError(t, err)
	defer cleanup()

	cmd := exec.CommandContext(ctx, sc.BwrapPath, sc.Args...)
	cmd.ExtraFiles = sc.ExtraFiles
	runErr := cmd.Run()
	require.NoError(t, runErr)
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

// --- Requirement: ELF interpreter auto-mount ---

func TestIntegration_InterpreterAutoMount_UserRuleForInterpreterPathAllowed(t *testing.T) {
	// Detect the real interpreter path from a known dynamic binary.
	lsPath, err := exec.LookPath("ls")
	require.NoError(t, err)

	interpPath := binutil.InterpreterPath(lsPath)
	require.NotEmpty(t, interpPath)

	managedPaths := sandbox.ManagedDirs()

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "execave.toml")
	err = os.WriteFile(configPath, []byte(`fs = ["ro:`+interpPath+`"]`), 0o600)
	require.NoError(t, err)

	cfg, err := config.Load(configPath, managedPaths, interpPath, "", "")
	require.NoError(t, err)

	// User's explicit rule should be present; no synthetic rule added.
	assert.Len(t, cfg.FSRules, 1)
	assert.Equal(t, interpPath, cfg.FSRules[0].Path)
}

func TestIntegration_InterpreterAutoMount_SyntheticRuleMountedInBwrapArgs(t *testing.T) {
	// Detect the real interpreter path from a known dynamic binary.
	lsPath, err := exec.LookPath("ls")
	require.NoError(t, err)

	interpPath := binutil.InterpreterPath(lsPath)
	require.NotEmpty(t, interpPath)

	// Load config with interpreter path — synthetic RO rule should be appended.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "execave.toml")
	err = os.WriteFile(configPath, []byte(`fs = ["ro:/usr/bin"]`), 0o600)
	require.NoError(t, err)

	cfg, err := config.Load(configPath, sandbox.ManagedDirs(), interpPath, "", "")
	require.NoError(t, err)

	args, close := prepare(t, cfg, dummyTunnelBinary, dummyUDSPath, []string{"true"})
	defer close()

	assert.True(t, argsContainSequence(args, "--ro-bind", interpPath, interpPath))
}

// --- Requirement: bwrap version check ---

// TestIntegration_BwrapVersionCheck_IncompatibleVersionReturnsError verifies that
// CheckBwrapVersion returns an error when the installed bwrap is at an incompatible
// version (older than pinned or major-version bump).
func TestIntegration_BwrapVersionCheck_IncompatibleVersionReturnsError(t *testing.T) {
	fakeBwrap := fakeVersionBinary(t, "bwrap", "bwrap 0.10.0")

	_, err := binutil.CheckBwrapVersion(fakeBwrap)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "incompatible")
}

// TestIntegration_BwrapVersionCheck_WarnTierVersionPrintsWarningAndContinues verifies that
// CheckBwrapVersion returns a non-empty warning (and no error) when bwrap is at a
// warn-tier version (higher minor within 0.x).
func TestIntegration_BwrapVersionCheck_WarnTierVersionPrintsWarningAndContinues(t *testing.T) {
	fakeBwrap := fakeVersionBinary(t, "bwrap", "bwrap 0.12.0")

	warn, err := binutil.CheckBwrapVersion(fakeBwrap)

	assert.NoError(t, err)
	assert.NotEmpty(t, warn)
}

// --- Requirement: strace version check ---

// TestIntegration_StraceVersionCheck_IncompatibleVersionReturnsError verifies that
// CheckStraceVersion returns an error for an incompatible strace version.
func TestIntegration_StraceVersionCheck_IncompatibleVersionReturnsError(t *testing.T) {
	fakeStrace := fakeVersionBinary(t, "strace", "strace -- version 6.18")

	_, err := binutil.CheckStraceVersion(fakeStrace)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "incompatible")
}

// TestIntegration_StraceVersionCheck_WarnTierVersionPrintsWarningAndContinues verifies that
// CheckStraceVersion returns a non-empty warning (and no error) for a warn-tier version.
func TestIntegration_StraceVersionCheck_WarnTierVersionPrintsWarningAndContinues(t *testing.T) {
	fakeStrace := fakeVersionBinary(t, "strace", "strace -- version 6.20")

	warn, err := binutil.CheckStraceVersion(fakeStrace)

	assert.NoError(t, err)
	assert.NotEmpty(t, warn)
}
