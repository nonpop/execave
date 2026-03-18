package e2e_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CLIRules_RuleTypeFlags(t *testing.T) {
	// Each CLI rule type flag (--fs, --net, --syscall, --env) adds rules on top of the
	// config file. Rules from both sources are merged and applied together.

	t.Run("--fs adds filesystem rule", func(t *testing.T) {
		s := newScenario(t)
		dataDir := s.givenDir("data")
		dataFile := dataDir.file("data.txt", "fs-cli-content")

		s.givenRules()
		s.givenCLIFlags("--fs", "ro:"+dataDir.String())
		s.whenRun("cat", dataFile)

		s.thenExitCode(0)
		s.thenStdoutContains("fs-cli-content")
	})

	t.Run("--fs multiple flags", func(t *testing.T) {
		s := newScenario(t)
		dir1 := s.givenDir("dir1")
		dir2 := s.givenDir("dir2")
		file1 := dir1.file("a.txt", "one")
		file2 := dir2.file("b.txt", "two")

		s.givenRules()
		s.givenCLIFlags("--fs", "ro:"+dir1.String(), "--fs", "ro:"+dir2.String())
		s.whenRun("sh", "-c", "cat "+file1+" && cat "+file2)

		s.thenExitCode(0)
		s.thenStdoutContains("one")
		s.thenStdoutContains("two")
	})

	t.Run("--net adds network rule", func(t *testing.T) {
		// Verify the rule is present in the merged config (net enforcement tested in restricting_network_test.go).
		s := newScenario(t)
		s.givenRules()
		s.givenCLIFlags("--net", "http:example.com:443")
		s.whenRunConfigShow()

		s.thenExitCode(0)
		s.thenStdoutContains("http:example.com:443")
	})

	t.Run("--syscall adds syscall allow rule", func(t *testing.T) {
		// Verify the rule is present in the merged config (syscall enforcement tested separately).
		s := newScenario(t)
		s.givenRules()
		s.givenCLIFlags("--syscall", "allow:ptrace")
		s.whenRunConfigShow()

		s.thenExitCode(0)
		s.thenStdoutContains("allow:ptrace")
	})

	t.Run("--env adds env pass rule", func(t *testing.T) {
		s := newScenario(t)
		t.Setenv("EXECAVE_CLI_TEST_VAR", "cli-env-value")

		s.givenRules() // no env:pass:EXECAVE_CLI_TEST_VAR in config
		s.givenCLIFlags("--env", "pass:EXECAVE_CLI_TEST_VAR")
		s.whenRun("sh", "-c", "echo ${EXECAVE_CLI_TEST_VAR:-absent}")

		s.thenExitCode(0)
		s.thenStdoutContains("cli-env-value")
	})
}

func Test_CLIRules_ExtendsFlag(t *testing.T) {
	// --extends loads a base config file via CLI, merging its rules.

	t.Run("--extends with config file: base rules apply", func(t *testing.T) {
		s := newScenario(t)
		dataDir := s.givenDir("data")
		dataFile := dataDir.file("data.txt", "extends-content")

		baseDir := testTempDir(t)
		basePath := filepath.Join(baseDir, "base.toml")
		require.NoError(t, os.WriteFile(basePath, tomlConfig([]string{"fs:ro:" + dataDir.String()}), 0o600))

		s.givenRules() // no dataDir rule in config
		s.givenCLIFlags("--extends", basePath)
		s.whenRun("cat", dataFile)

		s.thenExitCode(0)
		s.thenStdoutContains("extends-content")
	})

	t.Run("--extends with --no-config: only base rules apply", func(t *testing.T) {
		s := newScenario(t)
		dataDir := s.givenDir("data")
		dataFile := dataDir.file("data.txt", "noconfig-extends")

		baseDir := testTempDir(t)
		basePath := filepath.Join(baseDir, "base.toml")
		require.NoError(t, os.WriteFile(basePath, tomlConfig(append(systemPaths(), "fs:ro:"+dataDir.String())), 0o600))

		t.Run("base dir accessible", func(t *testing.T) {
			s := newScenario(t)
			s.givenCLIFlags("--no-config", "--extends", basePath)
			s.whenRun("cat", dataFile)

			s.thenExitCode(0)
			s.thenStdoutContains("noconfig-extends")
		})

		t.Run("config-only dir blocked", func(t *testing.T) {
			// Write a default config with an extra dir rule. With --no-config the config
			// is skipped entirely, so the extra dir must not be accessible.
			extraDir := s.givenDir("extra")
			extraFile := extraDir.file("extra.txt", "config-only-content")
			workDir := testTempDir(t)
			require.NoError(t, os.WriteFile(
				filepath.Join(workDir, "execave.toml"),
				tomlConfig(append(systemPaths(), "fs:ro:"+extraDir.String())),
				0o600,
			))

			s2 := newScenario(t)
			s2.givenCLIFlags("--no-config", "--extends", basePath)
			s2.givenWorkDir(workDir)
			s2.whenRun("cat", extraFile)

			s2.thenExitCodeNonZero()
		})
	})
}

func Test_CLIRules_NoConfig(t *testing.T) {
	// --no-config skips config file loading entirely; all rules must come from CLI flags.

	t.Run("CLI-only rules: command succeeds", func(t *testing.T) {
		s := newScenario(t)
		s.givenCLIFlags(
			"--no-config",
			"--fs", "ro:/usr",
			"--fs", "ro:/lib",
			"--fs", "ro:/lib64",
			"--fs", "ro:/etc/ld.so.cache",
			"--env", "pass:PATH",
		)
		s.whenRun("echo", "hello")

		s.thenExitCode(0)
		s.thenStdoutContains("hello")
	})

	t.Run("CLI-only with --fs rule: file accessible", func(t *testing.T) {
		s := newScenario(t)
		dataDir := s.givenDir("data")
		dataFile := dataDir.file("data.txt", "noconfig-fs")

		s.givenCLIFlags(
			"--no-config",
			"--fs", "ro:/usr",
			"--fs", "ro:/lib",
			"--fs", "ro:/lib64",
			"--fs", "ro:/etc/ld.so.cache",
			"--env", "pass:PATH",
			"--fs", "ro:"+dataDir.String(),
		)
		s.whenRun("cat", dataFile)

		s.thenExitCode(0)
		s.thenStdoutContains("noconfig-fs")
	})
}

func Test_CLIRules_ConfigNoConfigMutualExclusion(t *testing.T) {
	// --config and --no-config together are rejected before any command runs.
	s := newScenario(t)
	s.givenRules()
	s.givenCLIFlags("--no-config")
	s.whenRun("true")

	s.thenExitCode(1)
	s.thenStderrContains("--config")
	s.thenStderrContains("--no-config")
}

func Test_CLIRules_ConflictAndDeduplication(t *testing.T) {
	// CLI rules participate in the same duplicate-path/identity validation as file rules.
	// Conflicts across CLI and config are rejected; exact duplicates are silently deduped.
	errorCases := []struct {
		name       string
		configRule string
		cliFlag    string
		cliValue   string
		wantStderr string
	}{
		{
			name:       "fs path conflict: different permission",
			configRule: "fs:ro:/home/user/data",
			cliFlag:    "--fs",
			cliValue:   "rw:/home/user/data",
			wantStderr: "duplicate path",
		},
		{
			name:       "net identity conflict: same target different action",
			configRule: "net:http:example.com:443",
			cliFlag:    "--net",
			cliValue:   "none:example.com:443",
			wantStderr: "duplicate net rule",
		},
	}

	for _, tt := range errorCases {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRulesOnly(tt.configRule)
			s.givenCLIFlags(tt.cliFlag, tt.cliValue)
			s.whenRun("true")

			s.thenExitCode(1)
			s.thenStderrContains(tt.wantStderr)
		})
	}

	t.Run("fs exact duplicate: silently deduped", func(t *testing.T) {
		// /usr is already in systemPaths; adding it again via CLI is a duplicate and deduped.
		// Verify that /usr appears exactly once in the merged config output.
		s := newScenario(t)
		s.givenRules()
		s.givenCLIFlags("--fs", "ro:/usr")
		s.whenRunConfigShow()

		s.thenExitCode(0)
		assert.Equal(t, 1, strings.Count(s.lastResult.Stdout, `"ro:/usr"`))
	})
}

func Test_CLIRules_ConfigShow(t *testing.T) {
	// config show renders CLI-sourced rules with a # <cli> provenance comment.
	// With --no-config, only CLI rules appear.
	tests := []struct {
		name       string
		setup      func(s *scenario)
		wantExit   int
		wantStdout []string
	}{
		{
			name: "CLI rule shows # <cli> provenance",
			setup: func(s *scenario) {
				s.givenRules()
				s.givenCLIFlags("--fs", "ro:/cli-only-path")
			},
			wantExit:   0,
			wantStdout: []string{"# <cli>", `"ro:/cli-only-path",`},
		},
		{
			name: "--no-config with CLI rule: shows # <cli> and rule",
			setup: func(s *scenario) {
				s.givenCLIFlags("--no-config", "--fs", "ro:/nocfg-path")
			},
			wantExit:   0,
			wantStdout: []string{"# <cli>", `"ro:/nocfg-path",`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			tt.setup(s)
			s.whenRunConfigShow()

			s.thenExitCode(tt.wantExit)
			for _, sub := range tt.wantStdout {
				s.thenStdoutContains(sub)
			}
		})
	}
}

//nolint:funlen
func Test_CLIRules_InvalidSyntaxRejected(t *testing.T) {
	// Invalid CLI rule syntax is rejected at config load time; the command never runs.
	tests := []struct {
		name       string
		flag       string
		value      string
		wantStderr string
	}{
		{
			name:       "--fs missing permission prefix",
			flag:       "--fs",
			value:      "/usr/bin",
			wantStderr: "malformed rule",
		},
		{
			name:       "--fs invalid permission",
			flag:       "--fs",
			value:      "readwrite:/usr",
			wantStderr: "invalid permission type",
		},
		{
			name:       "--net missing port",
			flag:       "--net",
			value:      "http:example.com",
			wantStderr: "malformed rule",
		},
		{
			name:       "--syscall unknown action",
			flag:       "--syscall",
			value:      "deny:ptrace",
			wantStderr: "unknown syscall action",
		},
		{
			name:       "--env invalid action",
			flag:       "--env",
			value:      "allow:HOME",
			wantStderr: "invalid env rule action",
		},
		{
			name:       "--env pass HTTP_PROXY rejected",
			flag:       "--env",
			value:      "pass:HTTP_PROXY",
			wantStderr: "managed by the tunnel",
		},
		{
			name:       "--env pass HTTPS_PROXY rejected",
			flag:       "--env",
			value:      "pass:HTTPS_PROXY",
			wantStderr: "managed by the tunnel",
		},
		{
			name:       "--env pass no_proxy rejected",
			flag:       "--env",
			value:      "pass:no_proxy",
			wantStderr: "managed by the tunnel",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScenario(t)
			s.givenRules()
			s.givenCLIFlags(tt.flag, tt.value)
			s.whenRun("true")

			s.thenExitCode(1)
			s.thenStderrContains(tt.wantStderr)
		})
	}
}

func Test_CLIRules_FSPathExpansion(t *testing.T) {
	// CLI --fs paths are resolved relative to cwd (relative) or home dir (tilde).

	t.Run("relative path resolved against cwd", func(t *testing.T) {
		s := newScenario(t)
		workDir := s.givenDir("work")
		subDir := s.givenDir("work/data")
		dataFile := subDir.file("file.txt", "relative-content")

		s.givenRules()
		s.givenCLIFlags("--fs", "ro:./data")
		s.givenWorkDir(workDir.String())
		s.whenRun("cat", dataFile)

		s.thenExitCode(0)
		s.thenStdoutContains("relative-content")
	})

	t.Run("tilde path resolved against home dir", func(t *testing.T) {
		s := newScenario(t)
		homeDir, err := os.UserHomeDir()
		require.NoError(t, err)

		dataDir := s.givenDir("data")
		rel, err := filepath.Rel(homeDir, dataDir.String())
		require.NoError(t, err)
		require.False(t, filepath.IsAbs(rel), "test dir must be under home")

		dataFile := dataDir.file("tilde.txt", "tilde-content")

		s.givenRules()
		s.givenCLIFlags("--fs", "ro:~/"+rel)
		s.whenRun("cat", dataFile)

		s.thenExitCode(0)
		s.thenStdoutContains("tilde-content")
	})
}

func Test_CLIRules_MonitorCommand(t *testing.T) {
	// CLI rule flags work with the monitor subcommand.
	s := newScenario(t)
	failIfNoStrace(t)

	dataDir := s.givenDir("data")
	dataFile := dataDir.file("mon.txt", "monitor-cli")

	s.givenRules()
	s.givenCLIFlags("--fs", "ro:"+dataDir.String())
	s.whenRunTextLog("", "cat", dataFile)

	s.thenExitCode(0)
	s.thenStdoutContains("monitor-cli")
}

func Test_CLIRules_NoConfigSkipsMissingConfigFile(t *testing.T) {
	// --no-config does not require a config file to exist; a missing default config
	// is not an error when --no-config is set.
	s := newScenario(t)
	workDir := s.givenDir("work") // no execave.toml here

	s.givenCLIFlags(
		"--no-config",
		"--fs", "ro:/usr",
		"--fs", "ro:/lib",
		"--fs", "ro:/lib64",
		"--fs", "ro:/etc/ld.so.cache",
		"--env", "pass:PATH",
	)
	s.givenWorkDir(workDir.String())
	s.whenRun("echo", "hello")

	s.thenExitCode(0)
	s.thenStdoutContains("hello")
}
