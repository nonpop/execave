package e2e_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ConfiguringExecave_DefaultConfigLocation(t *testing.T) {
	// Without --config, execave reads ./execave.toml from the working directory.
	s := newScenario(t)
	workDir := s.givenDir("work")
	s.givenRulesInDir(workDir.String())

	s.whenRunWithDefaultConfig(workDir.String(), "echo", "hello")

	s.thenExitCode(0)
	s.thenStdoutContains("hello")
}

func Test_ConfiguringExecave_DefaultConfigLocationMissing(t *testing.T) {
	// Without --config and no ./execave.toml in the working directory, execave exits with a clear error.
	workDir := testTempDir(t)

	result := runExecave(t, workDir, "run", "--", "echo", "hello")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "file not found")
}

func Test_ConfiguringExecave_CustomConfigPathViaConfig(t *testing.T) {
	// --config makes execave read from the specified path instead of ./execave.toml;
	// any filename is accepted, not just "execave.toml".
	failIfNoBwrap(t)

	tests := []struct {
		name       string
		configName string
	}{
		{"standard filename", "execave.toml"},
		{"custom filename", "myconfig.toml"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configDir := testTempDir(t)
			configPath := filepath.Join(configDir, tc.configName)
			err := os.WriteFile(configPath, tomlConfig(systemPaths()), 0o600)
			require.NoError(t, err)

			// CWD is an empty dir with no execave.toml; success proves --config is used.
			workDir := testTempDir(t)
			result := runExecave(t, workDir, "--config", configPath, "--", "echo", "hello")

			assertExitCode(t, result, 0)
			assert.Contains(t, result.Stdout, "hello")
		})
	}
}

func Test_ConfiguringExecave_ExplicitAndImplicitRunEquivalent(t *testing.T) {
	// "execave run -- cmd" and "execave -- cmd" produce identical exit codes and output.
	s := newScenario(t)
	s.givenRules()

	// Successful command: stdout and exit code match.
	explicitOK := runExecave(t, "", "--config", s.configPath, "run", "--", "echo", "hello")
	implicitOK := runExecave(t, "", "--config", s.configPath, "--", "echo", "hello")
	assertExitCode(t, explicitOK, 0)
	assertExitCode(t, implicitOK, 0)
	assert.Equal(t, explicitOK.Stdout, implicitOK.Stdout)

	// Failing command: exit code is preserved and matches.
	explicitFail := runExecave(t, "", "--config", s.configPath, "run", "--", "sh", "-c", "exit 42")
	implicitFail := runExecave(t, "", "--config", s.configPath, "--", "sh", "-c", "exit 42")
	assertExitCode(t, explicitFail, 42)
	assertExitCode(t, implicitFail, 42)
}

func Test_ConfiguringExecave_MonitorFlagsRejectedOnRun(t *testing.T) {
	// Monitor-only flags are rejected immediately on the run subcommand with an
	// "unknown flag" error — no config loading or sandbox invocation occurs.
	tests := []struct {
		flag string
	}{
		{"--show-allowed"},
		{"--output-path"},
		{"--no-sandbox"},
	}

	for _, tc := range tests {
		t.Run(tc.flag, func(t *testing.T) {
			result := runExecave(t, "", "run", tc.flag, "--", "true")

			assertExitCode(t, result, 1)
			assert.Contains(t, result.Stderr, "unknown flag: "+tc.flag)
		})
	}
}

func Test_ConfiguringExecave_MissingConfigFileShowsError(t *testing.T) {
	// When --config points to a file that does not exist, execave exits with
	// exit code 1 and shows a clear error that includes the config path.
	tmpDir := testTempDir(t)
	tests := []struct {
		name      string
		workDir   string
		configArg string
		wantPath  string
	}{
		{
			name:      "absolute path",
			configArg: "/nonexistent/dir/config.toml",
			wantPath:  "/nonexistent/dir/config.toml",
		},
		{
			name:      "relative path",
			workDir:   tmpDir,
			configArg: "nonexistent.toml",
			wantPath:  filepath.Join(tmpDir, "nonexistent.toml"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := runExecave(t, tc.workDir, "--config", tc.configArg, "--", "true")

			assertExitCode(t, result, 1)
			assert.Contains(t, result.Stderr, "file not found")
			assert.Contains(t, result.Stderr, tc.wantPath)
		})
	}
}

func Test_ConfiguringExecave_InvalidRuleSyntaxRejectedBeforeExecution(t *testing.T) {
	// Malformed rules are rejected at config load time; the command never executes.
	tests := []struct {
		name       string
		rule       string
		wantStderr string
	}{
		{"invalid permission type", "fs:readonly:/home/user", "invalid permission type"},
		{"malformed rule (missing path)", "fs:ro", "malformed rule"},
		{"malformed net rule (missing port)", "net:http:example.com", "malformed rule"},
		{"tilde username syntax rejected", "fs:ro:~otheruser/data", "~username"},
		{"net port zero", "net:http:example.com:0", "invalid port"},
		{"net port above range", "net:http:example.com:99999", "invalid port"},
		{"net port negative", "net:http:example.com:-1", "invalid port"},
		{"net port non-numeric", "net:http:example.com:abc", "invalid port"},
		{"net bare wildcard domain", "net:http:*:443", "invalid domain pattern"},
		{"net deep wildcard domain", "net:http:*.*.example.com:443", "invalid domain pattern"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRulesOnly(tc.rule)

			s.whenRun("true")

			s.thenExitCode(1)
			s.thenStderrContains(tc.wantStderr)
		})
	}
}

func Test_ConfiguringExecave_BrokenTOMLSyntaxRejectedBeforeExecution(t *testing.T) {
	// A config file with invalid TOML syntax is rejected at parse time; the command never runs.
	s := newScenario(t)
	s.givenRawConfig("invalid toml [[[")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("parse")
}

func Test_ConfiguringExecave_UnknownConfigKeyRejectedBeforeExecution(t *testing.T) {
	// An unknown TOML key (e.g. "filesystem" instead of "fs") is rejected before execution,
	// preventing silent rule drops.
	s := newScenario(t)
	s.givenRawConfig(`filesystem = ["ro:/home/user"]`)

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("unknown config key")
	s.thenStderrContains("filesystem")
}

func Test_ConfiguringExecave_InvalidNetActionRejected(t *testing.T) {
	// Net rules with an unrecognized action are rejected at config load time.
	// Valid actions are "http" and "none"; anything else is a typo or a rule
	// from the wrong mental model. Without this check, the rule would be silently
	// dropped, leaving the user confused why their rule has no effect.
	tests := []struct {
		name string
		rule string
	}{
		{"https (natural but invalid)", "net:https:example.com:443"},
		{"dns (protocol from other paradigm)", "net:dns:example.com:53"},
		{"block (intuitive deny synonym)", "net:block:example.com:80"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRulesOnly(tc.rule)

			s.whenRun("true")

			s.thenExitCode(1)
			s.thenStderrContains("invalid action")
		})
	}
}

func Test_ConfiguringExecave_DuplicateFilesystemPathsRejected(t *testing.T) {
	// Two rules targeting the same normalized path are rejected with a clear error
	// identifying the duplicate, regardless of whether permissions differ or the paths
	// are written in different but equivalent forms.
	tests := []struct {
		name  string
		rules []string
	}{
		{"conflicting permissions", []string{"fs:ro:/home/user", "fs:rw:/home/user"}},
		{"same permissions", []string{"fs:ro:/home/user", "fs:ro:/home/user"}},
		{"trailing slash normalizes to same path", []string{"fs:ro:/home/user/", "fs:rw:/home/user"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRulesOnly(tc.rules...)

			s.whenRun("true")

			s.thenExitCode(1)
			s.thenStderrContains("duplicate path")
			s.thenStderrContains("/home/user")
		})
	}
}

func Test_ConfiguringExecave_TildeDuplicatePathRejected(t *testing.T) {
	// Two rules that resolve to the same absolute path after tilde expansion are rejected,
	// regardless of whether one or both rules use tilde notation.
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	dir := testTempDir(t)
	rel, err := filepath.Rel(homeDir, dir)
	require.NoError(t, err)
	require.False(t, filepath.IsAbs(rel))

	tilde := "~/" + rel

	tests := []struct {
		name  string
		rules []string
	}{
		{"tilde vs absolute", []string{"fs:ro:" + tilde, "fs:rw:" + dir}},
		{"tilde vs tilde", []string{"fs:ro:" + tilde, "fs:rw:" + tilde}},
		{"tilde trailing slash", []string{"fs:ro:" + tilde + "/", "fs:rw:" + tilde}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := runExecave(t, "", "--config", writeConfig(t, tc.rules), "--", "true")

			assertExitCode(t, result, 1)
			assert.Contains(t, result.Stderr, "duplicate path")
			assert.Contains(t, result.Stderr, dir)
		})
	}
}

func Test_ConfiguringExecave_DuplicateNetworkRuleIdentityRejected(t *testing.T) {
	// Two net rules sharing the same target and port pattern are rejected at config
	// load time, regardless of whether their actions differ or match.
	tests := []struct {
		name  string
		rules []string
	}{
		{"different actions same port", []string{"net:http:example.com:443", "net:none:example.com:443"}},
		{"same action same port", []string{"net:http:example.com:443", "net:http:example.com:443"}},
		{"different actions wildcard port", []string{"net:http:example.com:*", "net:none:example.com:*"}},
		{"different actions same CIDR", []string{"net:http:10.0.0.0/24:443", "net:none:10.0.0.0/24:443"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRules(tc.rules...)

			s.whenRun("true")

			s.thenExitCode(1)
			s.thenStderrContains("duplicate net rule")
		})
	}
}

func Test_ConfiguringExecave_MixedPortPatternsOnSameTargetRejected(t *testing.T) {
	// Mixing wildcard (*) and specific port rules for the same target is rejected at
	// config load time, regardless of rule order or whether the target is a domain or CIDR.
	tests := []struct {
		name  string
		rules []string
	}{
		{"domain wildcard then specific", []string{"net:http:example.com:*", "net:none:example.com:443"}},
		{"domain specific then wildcard", []string{"net:none:example.com:443", "net:http:example.com:*"}},
		{"CIDR wildcard then specific", []string{"net:http:10.0.0.0/24:*", "net:none:10.0.0.0/24:443"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRules(tc.rules...)

			s.whenRun("true")

			s.thenExitCode(1)
			s.thenStderrContains("mixed port patterns")
		})
	}
}

func Test_ConfiguringExecave_ValidNetRuleConfigurationsAccepted(t *testing.T) {
	// Valid net rule combinations are accepted at config load time: same target with
	// different ports, and different targets with different port styles.
	failIfNoBwrap(t)

	tests := []struct {
		name  string
		rules []string
	}{
		{"same target different ports", []string{"net:http:example.com:443", "net:http:example.com:80"}},
		{"different targets different port styles", []string{"net:http:example.com:*", "net:http:other.com:443"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRules(tc.rules...)

			s.whenRun("true")

			s.thenExitCode(0)
		})
	}
}

func Test_ConfiguringExecave_ConfigFileExplicitlyWritableRejected(t *testing.T) {
	// Explicitly granting rw access to the config file is rejected (privilege escalation risk);
	// ro access to the config file is allowed.
	failIfNoBwrap(t)

	tests := []struct {
		name       string
		perm       string
		useDir     bool
		wantExit   int
		wantStderr string
	}{
		{"rw rejected", "rw", false, 1, "must not be writable"},
		{"ro allowed", "ro", false, 0, ""},
		{"ro dir covers config path", "ro", true, 0, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := testTempDir(t)
			configPath := filepath.Join(tmpDir, "execave.toml")

			target := configPath
			if tc.useDir {
				target = tmpDir
			}
			rules := append(systemPaths(), "fs:"+tc.perm+":"+target)
			err := os.WriteFile(configPath, tomlConfig(rules), 0o600)
			require.NoError(t, err)

			result := runExecave(t, "", "--config", configPath, "--", "true")

			assertExitCode(t, result, tc.wantExit)
			if tc.wantStderr != "" {
				assert.Contains(t, result.Stderr, tc.wantStderr)
			}
		})
	}
}

func Test_ConfiguringExecave_ExtendedConfigMadeWritableRejected(t *testing.T) {
	// A child config that grants rw access to a base config file is rejected (privilege escalation risk).
	baseDir := testTempDir(t)
	basePath := filepath.Join(baseDir, "base.toml")
	require.NoError(t, os.WriteFile(basePath, tomlConfig(systemPaths()), 0o600))

	childDir := testTempDir(t)
	childPath := filepath.Join(childDir, "child.toml")
	childContent := fmt.Sprintf("extends = [%q]\n", basePath) + string(tomlConfig([]string{"fs:rw:" + basePath}))
	require.NoError(t, os.WriteFile(childPath, []byte(childContent), 0o600))

	result := runExecave(t, "", "--config", childPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "must not be writable")
	assert.Contains(t, result.Stderr, basePath)
}

func Test_ConfiguringExecave_ManagedPathsInRulesRejected(t *testing.T) {
	// Rules targeting managed paths (/proc, /dev, /tmp) or their descendants are
	// rejected at config load time before any command runs.
	tests := []struct {
		name string
		rule string
	}{
		{"exact /proc", "fs:ro:/proc"},
		{"descendant of /proc", "fs:ro:/proc/self/status"},
		{"exact /dev", "fs:ro:/dev"},
		{"exact /tmp", "fs:ro:/tmp"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRulesOnly(tc.rule)

			s.whenRun("true")

			s.thenExitCode(1)
			s.thenStderrContains("managed path")
		})
	}
}

func Test_ConfiguringExecave_PathSharingManagedNamePrefixAccepted(t *testing.T) {
	// A path whose final component shares a name with a managed path (e.g. "dev")
	// is not a managed path itself and must be accepted as a valid rule target.
	s := newScenario(t)
	dev := s.givenDir("dev")
	dev.file("hello.txt", "hello")
	s.givenRules("fs:ro:" + dev.String())

	s.whenRun("cat", dev.join("hello.txt"))

	s.thenExitCode(0)
	s.thenStdoutContains("hello")
}

func Test_ConfiguringExecave_TildeRuleExpandsAndMountsCorrectly(t *testing.T) {
	// ~/path in a rule expands to the home directory and the resulting path is mounted correctly.
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	t.Run("read-only", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		rel, err := filepath.Rel(homeDir, data.String())
		require.NoError(t, err)
		require.False(t, filepath.IsAbs(rel))

		dataFile := data.file("data.txt", "tilde content")
		s.givenRules("fs:ro:~/" + rel)

		s.whenRun("cat", dataFile)

		s.thenExitCode(0)
		s.thenStdoutContains("tilde content")
	})

	t.Run("read-write", func(t *testing.T) {
		s := newScenario(t)
		data := s.givenDir("data")
		rel, err := filepath.Rel(homeDir, data.String())
		require.NoError(t, err)
		require.False(t, filepath.IsAbs(rel))

		outFile := data.join("out.txt")
		s.givenRules("fs:rw:~/" + rel)

		s.whenRun("sh", "-c", "echo written > "+outFile+" && cat "+outFile)

		s.thenExitCode(0)
		s.thenStdoutContains("written")
	})
}

func Test_ConfigFileFormat_TOMLSyntaxFeatures(t *testing.T) {
	// TOML syntax features (comments, trailing commas) are silently ignored; the config loads and rules apply normally.
	t.Run("comments", func(t *testing.T) {
		s := newScenario(t)
		s.givenRawConfig(`# Sandbox config
fs = [
    # System libraries
    "ro:/usr",
    "ro:/lib",
    "ro:/lib64",
    "ro:/etc/ld.so.cache",  # linker cache
]`)

		s.whenRun("echo", "hello")

		s.thenExitCode(0)
		s.thenStdoutContains("hello")
	})

	t.Run("trailing comma", func(t *testing.T) {
		s := newScenario(t)
		s.givenRawConfig(`fs = ["ro:/usr", "ro:/lib", "ro:/lib64", "ro:/etc/ld.so.cache",]`)

		s.whenRun("echo", "hello")

		s.thenExitCode(0)
		s.thenStdoutContains("hello")
	})
}

func Test_ConfiguringExecave_SelectivelyAllowABlockedSyscall(t *testing.T) {
	// Without syscall:allow:bpf, seccomp blocks bpf and the process receives EPERM (1).
	// With the rule, the syscall reaches the kernel, which returns EINVAL (22) for invalid args.
	requireAMD64(t)

	// Python one-liner: call bpf(0,0,0) via libc.syscall(321,...) and print errno.
	const callBpfPrintErrno = "import ctypes,ctypes.util;lib=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True);lib.syscall(321,0,0,0);print(ctypes.get_errno())"

	tests := []struct {
		name       string
		extraRules []string
		wantErrno  string
	}{
		{"blocked by default", nil, "1"},                          // EPERM from seccomp
		{"allowed via rule", []string{"syscall:allow:bpf"}, "22"}, // EINVAL from kernel
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenPython3()
			s.givenRules(tc.extraRules...)

			s.whenRun("python3", "-c", callBpfPrintErrno)

			s.thenExitCode(0)
			s.thenStdoutContains(tc.wantErrno)
		})
	}
}

func Test_ConfiguringExecave_InvalidSyscallNameRejectedAtConfigParse(t *testing.T) {
	// A misspelled, fake, or non-blocked syscall name in a syscall:allow rule is
	// rejected at config load time; the command never runs.
	tests := []struct {
		name string
		rule string
		want string
	}{
		{"typo of ptrace", "syscall:allow:ptraec", "ptraec"},
		{"completely fake name", "syscall:allow:fakesyscall", "fakesyscall"},
		{"real syscall not in blocked set", "syscall:allow:read", "read"},
		{"missing syscall name", "syscall:allow:", "malformed syscall rule"},
		{"missing colon in syscall rule", "syscall:allow", "malformed syscall rule"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRulesOnly(tc.rule)

			s.whenRun("true")

			s.thenExitCode(1)
			s.thenStderrContains(tc.want)
		})
	}
}

func Test_ConfiguringExecave_DefenseInDepthSyscallRejectedAtConfigParse(t *testing.T) {
	// Syscalls blocked by kernel capabilities inside the sandbox (defense-in-depth) cannot
	// be allowed via config rules and are rejected at parse time.
	result := runExecave(t, "", "--config", writeConfig(t, []string{"syscall:allow:syslog"}), "--", "ls")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "syslog")
}

func Test_ConfiguringExecave_MultipleSyscallRules(t *testing.T) {
	// Multiple syscall:allow rules all take effect simultaneously: each listed syscall
	// independently bypasses the seccomp filter and appears in the access log matched
	// to its specific rule.
	requireAMD64(t)
	s := newScenario(t)
	s.givenPython3()
	s.givenRules("syscall:allow:bpf", "syscall:allow:reboot")

	// Invoke both syscalls; reboot uses invalid magic (0,0,0) so it returns EINVAL, not actually rebooting.
	s.whenRunTextLogWithFlags([]string{"--show-allowed"}, "python3", "-c", bpfRebootPythonCmd)

	s.thenStderrHasEntry("SYSCALL", "bpf", "OK", "allow:bpf")
	s.thenStderrHasEntry("SYSCALL", "reboot", "OK", "allow:reboot")
}

func Test_ConfiguringExecave_DuplicateSyscallAllowRulesRejected(t *testing.T) {
	// Two syscall:allow rules for the same syscall name are rejected at config parse time.
	s := newScenario(t)
	s.givenRulesOnly("syscall:allow:ptrace", "syscall:allow:ptrace")

	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("duplicate")
	s.thenStderrContains("ptrace")
}

func Test_ConfiguringExecave_SyscallNologRuleRejected(t *testing.T) {
	// A syscall rule with an unrecognized action is rejected at config parse time;
	// the command never runs.
	tests := []struct {
		name string
		rule string
	}{
		{"nolog (removed action)", "syscall:nolog:ptrace"},
		{"deny (intuitive but invalid)", "syscall:deny:ptrace"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRulesOnly(tc.rule)

			s.whenRun("true")

			s.thenExitCode(1)
			s.thenStderrContains("unknown syscall action")
		})
	}
}

func Test_ConfiguringExecave_CrossFileConflictingRulesRejectedWithSourceFilePaths(t *testing.T) {
	// When rules from different config files conflict, the error includes both source
	// file paths so the user knows which files to edit to resolve the conflict.

	t.Run("fs conflict includes both file paths", func(t *testing.T) {
		dataDir := testTempDir(t)
		baseDir := testTempDir(t)
		basePath := filepath.Join(baseDir, "base.toml")
		require.NoError(t, os.WriteFile(basePath, tomlConfig([]string{"fs:ro:" + dataDir}), 0o600))

		childDir := testTempDir(t)
		childPath := filepath.Join(childDir, "child.toml")
		childContent := fmt.Sprintf("extends = [%q]\n", basePath) + string(tomlConfig([]string{"fs:rw:" + dataDir}))
		require.NoError(t, os.WriteFile(childPath, []byte(childContent), 0o600))

		result := runExecave(t, "", "--config", childPath, "--", "true")

		assertExitCode(t, result, 1)
		assert.Contains(t, result.Stderr, "duplicate path")
		assert.Contains(t, result.Stderr, basePath)
		assert.Contains(t, result.Stderr, childPath)
	})

	t.Run("net conflict includes both file paths", func(t *testing.T) {
		baseDir := testTempDir(t)
		basePath := filepath.Join(baseDir, "base.toml")
		require.NoError(t, os.WriteFile(basePath, tomlConfig([]string{"net:http:example.com:443"}), 0o600))

		childDir := testTempDir(t)
		childPath := filepath.Join(childDir, "child.toml")
		childContent := fmt.Sprintf("extends = [%q]\n", basePath) + string(tomlConfig([]string{"net:none:example.com:443"}))
		require.NoError(t, os.WriteFile(childPath, []byte(childContent), 0o600))

		result := runExecave(t, "", "--config", childPath, "--", "true")

		assertExitCode(t, result, 1)
		assert.Contains(t, result.Stderr, "duplicate net rule identity")
		assert.Contains(t, result.Stderr, basePath)
		assert.Contains(t, result.Stderr, childPath)
	})

	t.Run("three-level chain fs conflict includes grandparent and grandchild paths", func(t *testing.T) {
		dataDir := testTempDir(t)
		grandparentDir := testTempDir(t)
		grandparentPath := filepath.Join(grandparentDir, "grandparent.toml")
		require.NoError(t, os.WriteFile(grandparentPath, tomlConfig([]string{"fs:ro:" + dataDir}), 0o600))

		parentDir := testTempDir(t)
		parentPath := filepath.Join(parentDir, "parent.toml")
		require.NoError(t, os.WriteFile(parentPath, []byte(fmt.Sprintf("extends = [%q]\n", grandparentPath)), 0o600))

		childDir := testTempDir(t)
		childPath := filepath.Join(childDir, "child.toml")
		childContent := fmt.Sprintf("extends = [%q]\n", parentPath) + string(tomlConfig([]string{"fs:rw:" + dataDir}))
		require.NoError(t, os.WriteFile(childPath, []byte(childContent), 0o600))

		result := runExecave(t, "", "--config", childPath, "--", "true")

		assertExitCode(t, result, 1)
		assert.Contains(t, result.Stderr, "duplicate path")
		assert.Contains(t, result.Stderr, grandparentPath)
		assert.Contains(t, result.Stderr, childPath)
	})
}

func Test_ConfiguringExecave_CyclicExtendsChainIsRejected(t *testing.T) {
	// A cyclic extends chain is detected and rejected with a clear error before any
	// command runs, regardless of cycle length.

	t.Run("two-file cycle", func(t *testing.T) {
		dir := testTempDir(t)
		aPath := filepath.Join(dir, "a.toml")
		bPath := filepath.Join(dir, "b.toml")
		require.NoError(t, os.WriteFile(aPath, []byte(fmt.Sprintf("extends = [%q]\n", bPath)), 0o600))
		require.NoError(t, os.WriteFile(bPath, []byte(fmt.Sprintf("extends = [%q]\n", aPath)), 0o600))

		result := runExecave(t, "", "--config", aPath, "--", "true")

		assertExitCode(t, result, 1)
		assert.Contains(t, result.Stderr, "cycle")
	})

	t.Run("self-reference", func(t *testing.T) {
		dir := testTempDir(t)
		aPath := filepath.Join(dir, "a.toml")
		require.NoError(t, os.WriteFile(aPath, []byte(fmt.Sprintf("extends = [%q]\n", aPath)), 0o600))

		result := runExecave(t, "", "--config", aPath, "--", "true")

		assertExitCode(t, result, 1)
		assert.Contains(t, result.Stderr, "cycle")
	})
}

func Test_ConfiguringExecave_ComposeProjectConfigFromSharedBaseFiles(t *testing.T) {
	// An extends chain merges rules from all files; commands can access resources
	// permitted by any file in the chain. Exact duplicate rules across files are
	// silently deduplicated. A missing extends target exits with a clear error.

	t.Run("base rules apply in child config", func(t *testing.T) {
		failIfNoBwrap(t)

		dataDir := testTempDir(t)
		dataFile := filepath.Join(dataDir, "data.txt")
		require.NoError(t, os.WriteFile(dataFile, []byte("from base rule"), 0o600))

		baseDir := testTempDir(t)
		basePath := filepath.Join(baseDir, "base.toml")
		require.NoError(t, os.WriteFile(basePath, tomlConfig(append(systemPaths(), "fs:ro:"+dataDir)), 0o600))

		projectDir := testTempDir(t)
		projectPath := filepath.Join(projectDir, "execave.toml")
		require.NoError(t, os.WriteFile(projectPath, []byte(fmt.Sprintf("extends = [%q]\n", basePath)), 0o600))

		result := runExecave(t, "", "--config", projectPath, "--", "cat", dataFile)

		assertExitCode(t, result, 0)
		assert.Contains(t, result.Stdout, "from base rule")
	})

	t.Run("three-level chain merges rules from all files", func(t *testing.T) {
		failIfNoBwrap(t)

		dataDir := testTempDir(t)
		dataFile := filepath.Join(dataDir, "data.txt")
		require.NoError(t, os.WriteFile(dataFile, []byte("chained"), 0o600))

		grandparentDir := testTempDir(t)
		grandparentPath := filepath.Join(grandparentDir, "grandparent.toml")
		require.NoError(t, os.WriteFile(grandparentPath, tomlConfig(systemPaths()), 0o600))

		parentDir := testTempDir(t)
		parentPath := filepath.Join(parentDir, "parent.toml")
		parentContent := fmt.Sprintf("extends = [%q]\n", grandparentPath) + string(tomlConfig([]string{"fs:ro:" + dataDir}))
		require.NoError(t, os.WriteFile(parentPath, []byte(parentContent), 0o600))

		projectDir := testTempDir(t)
		projectPath := filepath.Join(projectDir, "execave.toml")
		require.NoError(t, os.WriteFile(projectPath, []byte(fmt.Sprintf("extends = [%q]\n", parentPath)), 0o600))

		result := runExecave(t, "", "--config", projectPath, "--", "cat", dataFile)

		assertExitCode(t, result, 0)
		assert.Contains(t, result.Stdout, "chained")
	})

	t.Run("exact duplicate rule across files is silently deduplicated", func(t *testing.T) {
		failIfNoBwrap(t)

		dataDir := testTempDir(t)
		dataFile := filepath.Join(dataDir, "data.txt")
		require.NoError(t, os.WriteFile(dataFile, []byte("deduped"), 0o600))

		baseDir := testTempDir(t)
		basePath := filepath.Join(baseDir, "base.toml")
		require.NoError(t, os.WriteFile(basePath, tomlConfig(append(systemPaths(), "fs:ro:"+dataDir)), 0o600))

		// project declares the same ro:dataDir rule as base — should be silently deduped
		projectDir := testTempDir(t)
		projectPath := filepath.Join(projectDir, "execave.toml")
		projectContent := fmt.Sprintf("extends = [%q]\n", basePath) + string(tomlConfig([]string{"fs:ro:" + dataDir}))
		require.NoError(t, os.WriteFile(projectPath, []byte(projectContent), 0o600))

		result := runExecave(t, "", "--config", projectPath, "--", "cat", dataFile)

		assertExitCode(t, result, 0)
		assert.Contains(t, result.Stdout, "deduped")
	})

	t.Run("syscall duplicate rule across files is silently deduplicated", func(t *testing.T) {
		failIfNoBwrap(t)

		baseDir := testTempDir(t)
		basePath := filepath.Join(baseDir, "base.toml")
		require.NoError(t, os.WriteFile(basePath, tomlConfig(append(systemPaths(), "syscall:allow:ptrace")), 0o600))

		projectDir := testTempDir(t)
		projectPath := filepath.Join(projectDir, "execave.toml")
		projectContent := fmt.Sprintf("extends = [%q]\n", basePath) + string(tomlConfig([]string{"syscall:allow:ptrace"}))
		require.NoError(t, os.WriteFile(projectPath, []byte(projectContent), 0o600))

		result := runExecave(t, "", "--config", projectPath, "--", "true")

		assertExitCode(t, result, 0)
	})

	t.Run("missing extends target exits with clear error", func(t *testing.T) {
		projectDir := testTempDir(t)
		projectPath := filepath.Join(projectDir, "execave.toml")
		missingPath := filepath.Join(projectDir, "nonexistent.toml")
		require.NoError(t, os.WriteFile(projectPath, []byte(fmt.Sprintf("extends = [%q]\n", missingPath)), 0o600))

		result := runExecave(t, "", "--config", projectPath, "--", "true")

		assertExitCode(t, result, 1)
		assert.Contains(t, result.Stderr, "file not found")
		assert.Contains(t, result.Stderr, missingPath)
	})
}

func Test_ConfiguringExecave_ExtendsPathsResolveWithAbsoluteRelativeAndTildeForms(t *testing.T) {
	// extends paths resolve correctly regardless of whether they use absolute,
	// relative (same dir or parent dir), or tilde forms; the base config is loaded
	// and its rules merged into the effective config in all cases.
	failIfNoBwrap(t)

	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	// Create base config once; all sub-tests reference it in different path forms.
	baseDir := testTempDir(t)
	dataFile := filepath.Join(baseDir, "data.txt")
	require.NoError(t, os.WriteFile(dataFile, []byte("extends-content"), 0o600))
	basePath := filepath.Join(baseDir, "base.toml")
	require.NoError(t, os.WriteFile(basePath, tomlConfig(append(systemPaths(), "fs:ro:"+baseDir)), 0o600))

	relFromHome, err := filepath.Rel(homeDir, basePath)
	require.NoError(t, err)
	// Base config must be under the home directory for the tilde sub-test to work.
	require.False(t, filepath.IsAbs(relFromHome))

	tests := []struct {
		name         string
		projectSetup func(t *testing.T) string // returns project config path
	}{
		{
			name: "absolute path",
			projectSetup: func(t *testing.T) string {
				t.Helper()
				dir := testTempDir(t)
				path := filepath.Join(dir, "execave.toml")
				require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("extends = [%q]\n", basePath)), 0o600))
				return path
			},
		},
		{
			name: "relative path same directory",
			projectSetup: func(t *testing.T) string {
				t.Helper()
				path := filepath.Join(baseDir, "execave.toml")
				require.NoError(t, os.WriteFile(path, []byte("extends = [\"base.toml\"]\n"), 0o600))
				return path
			},
		},
		{
			name: "relative path parent directory",
			projectSetup: func(t *testing.T) string {
				t.Helper()
				sub := filepath.Join(baseDir, "sub")
				require.NoError(t, os.MkdirAll(sub, 0o750))
				path := filepath.Join(sub, "execave.toml")
				require.NoError(t, os.WriteFile(path, []byte("extends = [\"../base.toml\"]\n"), 0o600))
				return path
			},
		},
		{
			name: "tilde path",
			projectSetup: func(t *testing.T) string {
				t.Helper()
				dir := testTempDir(t)
				path := filepath.Join(dir, "execave.toml")
				require.NoError(t, os.WriteFile(path, []byte(fmt.Sprintf("extends = [%q]\n", "~/"+relFromHome)), 0o600))
				return path
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			projectPath := tc.projectSetup(t)

			result := runExecave(t, "", "--config", projectPath, "--", "cat", dataFile)

			assertExitCode(t, result, 0)
			assert.Contains(t, result.Stdout, "extends-content")
		})
	}
}

func Test_ConfiguringExecave_MissingBwrapProducesClearError(t *testing.T) {
	// When bwrap is not in PATH, execave exits with a clear error naming bwrap.
	t.Setenv("PATH", t.TempDir())

	configPath := writeConfig(t, systemPaths())
	result := runExecave(t, "", "--config", configPath, "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "bwrap")
}

func Test_ConfiguringExecave_MissingStraceProducesClearErrorWhenMonitoringRequested(t *testing.T) {
	// When strace is not in PATH and monitoring is requested, execave exits with a clear error naming strace.
	t.Setenv("PATH", t.TempDir())

	configPath := writeConfig(t, systemPaths())
	result := runExecave(t, "", "--config", configPath, "monitor", "--", "true")

	assertExitCode(t, result, 1)
	assert.Contains(t, result.Stderr, "strace")
}
