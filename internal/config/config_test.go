package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// loadTestConfig writes content to a temp file and loads it as a config.
func loadTestConfig(t *testing.T, content string) (*config.Config, error) {
	t.Helper()
	configPath := writeTestConfig(t, content)
	return config.Load(configPath, config.CLIRules{FS: nil, Net: nil, Syscall: nil, Env: nil, Extends: nil, NoConfig: false, ConfigExplicitlySet: false}, nil, "", "", "") //nolint:wrapcheck
}

// writeTestConfig writes content to a temp config file and returns the path.
func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "execave.toml")
	err := os.WriteFile(configPath, []byte(content), 0o600)
	require.NoError(t, err)
	return configPath
}

func writeConfigFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	err := os.WriteFile(path, []byte(content), 0o600)
	require.NoError(t, err)
	return path
}

func TestLoad_ExtendsRelativePath(t *testing.T) {
	dir := t.TempDir()
	basePath := writeConfigFile(t, dir, "base.toml", `fs = ["ro:/usr/bin"]`)
	rootContent := `
extends = ["base.toml"]
fs = ["ro:/home/project"]
`
	rootPath := writeConfigFile(t, dir, "execave.toml", rootContent)

	cfg, err := config.Load(rootPath, config.CLIRules{FS: nil, Net: nil, Syscall: nil, Env: nil, Extends: nil, NoConfig: false, ConfigExplicitlySet: false}, nil, "", "", "")
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 2)
	assert.Equal(t, []string{basePath, rootPath, config.SourceCLI, config.SourceSynthetic}, cfg.ConfigPaths)
}

func TestLoad_ExtendsTildeExpansion(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	writeConfigFile(t, homeDir, "shared.toml", `fs = ["ro:/etc/shared"]`)

	rootDir := t.TempDir()
	rootContent := `
extends = ["~/shared.toml"]
fs = ["ro:/var/log"]
`
	rootPath := writeConfigFile(t, rootDir, "execave.toml", rootContent)

	cfg, err := config.Load(rootPath, config.CLIRules{FS: nil, Net: nil, Syscall: nil, Env: nil, Extends: nil, NoConfig: false, ConfigExplicitlySet: false}, nil, "", "", "")
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 2)
	assert.Equal(t, []string{filepath.Join(homeDir, "shared.toml"), rootPath, config.SourceCLI, config.SourceSynthetic}, cfg.ConfigPaths)
}

func TestValidate_NoneWithChildAllowed(t *testing.T) {
	cfg, err := loadTestConfig(t, `fs = [
	"none:/home/user/project/.env",
	"ro:/home/user/project/.env/example",
]`)
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 2)
}

func TestValidate_NoneTerminalValid(t *testing.T) {
	_, err := loadTestConfig(t, `fs = [
	"rw:/home/user/project",
	"none:/home/user/project/.env",
]`)
	assert.NoError(t, err)
}

func TestValidate_ManagedPath_SimilarNameAllowed(t *testing.T) {
	managedPaths := []string{"/proc", "/dev", "/tmp"}

	// Paths that look similar but aren't under managed dirs
	tests := []struct {
		name string
		rule string
	}{
		{"proc in name", `"ro:/home/user/proc"`},
		{"procfile", `"ro:/home/user/procfile"`},
		{"dev in project", `"rw:/home/user/dev"`},
		{"tmpdir", `"rw:/home/user/tmpdir"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := `fs = [` + tt.rule + `]`
			configPath := writeTestConfig(t, content)

			_, err := config.Load(configPath, config.CLIRules{FS: nil, Net: nil, Syscall: nil, Env: nil, Extends: nil, NoConfig: false, ConfigExplicitlySet: false}, managedPaths, "", "", "")
			assert.NoError(t, err)
		})
	}
}

func TestPermission_Strictness(t *testing.T) {
	// Higher values are more permissive; Unknown is below None so unhandled
	// Unknown values are at least as strict as an explicit deny.
	assert.Less(t, fsrules.PermissionUnknown, fsrules.PermissionNone)
	assert.Less(t, fsrules.PermissionNone, fsrules.PermissionReadOnly)
	assert.Less(t, fsrules.PermissionReadOnly, fsrules.PermissionReadWrite)
}

func TestLoad_InterpreterRule_AddedWhenNotCovered(t *testing.T) {
	configPath := writeTestConfig(t, `fs = ["ro:/usr/bin"]`)
	cfg, err := config.Load(configPath, config.CLIRules{FS: nil, Net: nil, Syscall: nil, Env: nil, Extends: nil, NoConfig: false, ConfigExplicitlySet: false}, nil, "/lib64/ld-linux-x86-64.so.2", "", "")
	require.NoError(t, err)

	require.Len(t, cfg.FSRules, 2)
	synthetic := cfg.FSRules[1]
	assert.Equal(t, fsrules.PermissionReadOnly, synthetic.Permission)
	assert.Equal(t, "/lib64/ld-linux-x86-64.so.2", synthetic.Path)
	assert.Equal(t, "ro:/lib64/ld-linux-x86-64.so.2", synthetic.RawRule)
	assert.Equal(t, config.SourceSynthetic, synthetic.SourcePath)
}

func TestLoad_InterpreterRule_NotAddedWhenReadOnly(t *testing.T) {
	configPath := writeTestConfig(t, `fs = ["ro:/lib64"]`)
	cfg, err := config.Load(configPath, config.CLIRules{FS: nil, Net: nil, Syscall: nil, Env: nil, Extends: nil, NoConfig: false, ConfigExplicitlySet: false}, nil, "/lib64/ld-linux-x86-64.so.2", "", "")
	require.NoError(t, err)

	assert.Len(t, cfg.FSRules, 1)
}

func TestLoad_InterpreterRule_NotAddedWhenReadWrite(t *testing.T) {
	configPath := writeTestConfig(t, `fs = ["rw:/lib64"]`)
	cfg, err := config.Load(configPath, config.CLIRules{FS: nil, Net: nil, Syscall: nil, Env: nil, Extends: nil, NoConfig: false, ConfigExplicitlySet: false}, nil, "/lib64/ld-linux-x86-64.so.2", "", "")
	require.NoError(t, err)

	assert.Len(t, cfg.FSRules, 1)
}

func TestLoad_InterpreterRule_EmptyPath(t *testing.T) {
	configPath := writeTestConfig(t, `fs = ["ro:/usr/bin"]`)
	cfg, err := config.Load(configPath, config.CLIRules{FS: nil, Net: nil, Syscall: nil, Env: nil, Extends: nil, NoConfig: false, ConfigExplicitlySet: false}, nil, "", "", "")
	require.NoError(t, err)

	assert.Len(t, cfg.FSRules, 1)
}

func TestLoad_TunnelPaths_BothUncovered_BothRulesAdded(t *testing.T) {
	configPath := writeTestConfig(t, `fs = ["ro:/usr/bin"]`)
	cfg, err := config.Load(configPath, config.CLIRules{FS: nil, Net: nil, Syscall: nil, Env: nil, Extends: nil, NoConfig: false, ConfigExplicitlySet: false}, nil, "", "/usr/local/bin/execave", "/run/user/1000/execave-xyz/proxy.sock")
	require.NoError(t, err)

	require.Len(t, cfg.FSRules, 3)
	assert.Equal(t, "/usr/local/bin/execave", cfg.FSRules[1].Path)
	assert.Equal(t, fsrules.PermissionReadOnly, cfg.FSRules[1].Permission)
	assert.Equal(t, "/run/user/1000/execave-xyz/proxy.sock", cfg.FSRules[2].Path)
	assert.Equal(t, fsrules.PermissionReadOnly, cfg.FSRules[2].Permission)
}

func TestLoad_TunnelPaths_BinaryAlreadyCoveredByParentRORule_OnlyUDSRuleAdded(t *testing.T) {
	configPath := writeTestConfig(t, `fs = ["ro:/usr/local/bin"]`)
	cfg, err := config.Load(configPath, config.CLIRules{FS: nil, Net: nil, Syscall: nil, Env: nil, Extends: nil, NoConfig: false, ConfigExplicitlySet: false}, nil, "", "/usr/local/bin/execave", "/run/user/1000/execave-xyz/proxy.sock")
	require.NoError(t, err)

	require.Len(t, cfg.FSRules, 2)
	assert.Equal(t, "/usr/local/bin", cfg.FSRules[0].Path)
	assert.Equal(t, "/run/user/1000/execave-xyz/proxy.sock", cfg.FSRules[1].Path)
}

func TestLoad_TunnelPaths_EmptyPaths_NoRulesAdded(t *testing.T) {
	configPath := writeTestConfig(t, `fs = ["ro:/usr/bin"]`)
	cfg, err := config.Load(configPath, config.CLIRules{FS: nil, Net: nil, Syscall: nil, Env: nil, Extends: nil, NoConfig: false, ConfigExplicitlySet: false}, nil, "", "", "")
	require.NoError(t, err)

	assert.Len(t, cfg.FSRules, 1)
}

func TestLoad_CLIOnlyNoConfig(t *testing.T) {
	cliRules := config.CLIRules{
		FS:                  []string{"ro:/usr/bin"},
		Net:                 nil,
		Syscall:             nil,
		Env:                 nil,
		Extends:             nil,
		NoConfig:            true,
		ConfigExplicitlySet: false,
	}
	cfg, err := config.Load("nonexistent.toml", cliRules, nil, "", "", "")
	require.NoError(t, err)
	require.Len(t, cfg.FSRules, 1)
	assert.Equal(t, "/usr/bin", cfg.FSRules[0].Path)
	assert.Equal(t, config.SourceCLI, cfg.FSRules[0].SourcePath)
	assert.Equal(t, []string{config.SourceCLI, config.SourceSynthetic}, cfg.ConfigPaths)
}

func TestLoad_CLIRulesMergedWithConfigFile(t *testing.T) {
	cfgPath := writeTestConfig(t, `fs = ["ro:/etc"]`)
	cliRules := config.CLIRules{
		FS:                  []string{"ro:/usr/bin"},
		Net:                 nil,
		Syscall:             nil,
		Env:                 nil,
		Extends:             nil,
		NoConfig:            false,
		ConfigExplicitlySet: false,
	}
	cfg, err := config.Load(cfgPath, cliRules, nil, "", "", "")
	require.NoError(t, err)
	require.Len(t, cfg.FSRules, 2)
	// config file rule comes first (base); CLI rule comes after
	assert.Equal(t, "/etc", cfg.FSRules[0].Path)
	assert.Equal(t, cfgPath, cfg.FSRules[0].SourcePath)
	assert.Equal(t, "/usr/bin", cfg.FSRules[1].Path)
	assert.Equal(t, config.SourceCLI, cfg.FSRules[1].SourcePath)
	assert.Equal(t, []string{cfgPath, config.SourceCLI, config.SourceSynthetic}, cfg.ConfigPaths)
}

func TestLoad_DuplicateRuleDeduplicated(t *testing.T) {
	cfgPath := writeTestConfig(t, `fs = ["ro:/usr/bin"]`)
	cliRules := config.CLIRules{
		FS:                  []string{"ro:/usr/bin"}, // same rule as config
		Net:                 nil,
		Syscall:             nil,
		Env:                 nil,
		Extends:             nil,
		NoConfig:            false,
		ConfigExplicitlySet: false,
	}
	cfg, err := config.Load(cfgPath, cliRules, nil, "", "", "")
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
}

func TestLoad_ConflictBetweenCLIAndConfig(t *testing.T) {
	cfgPath := writeTestConfig(t, `fs = ["rw:/home/user/project"]`)
	cliRules := config.CLIRules{
		FS:                  []string{"ro:/home/user/project"}, // conflicts: rw vs ro same path
		Net:                 nil,
		Syscall:             nil,
		Env:                 nil,
		Extends:             nil,
		NoConfig:            false,
		ConfigExplicitlySet: false,
	}
	_, err := config.Load(cfgPath, cliRules, nil, "", "", "")
	assert.Error(t, err)
}

func TestLoad_ExtendsViaCLIFlag(t *testing.T) {
	dir := t.TempDir()
	basePath := writeConfigFile(t, dir, "base.toml", `fs = ["ro:/usr/lib"]`)
	cliRules := config.CLIRules{
		FS:                  []string{"ro:/usr/bin"},
		Net:                 nil,
		Syscall:             nil,
		Env:                 nil,
		Extends:             []string{basePath},
		NoConfig:            true,
		ConfigExplicitlySet: false,
	}
	cfg, err := config.Load("nonexistent.toml", cliRules, nil, "", "", "")
	require.NoError(t, err)
	require.Len(t, cfg.FSRules, 2)
	assert.Equal(t, "/usr/lib", cfg.FSRules[0].Path)
	assert.Equal(t, basePath, cfg.FSRules[0].SourcePath)
	assert.Equal(t, "/usr/bin", cfg.FSRules[1].Path)
	assert.Equal(t, config.SourceCLI, cfg.FSRules[1].SourcePath)
	assert.Equal(t, []string{basePath, config.SourceCLI, config.SourceSynthetic}, cfg.ConfigPaths)
}

func TestLoad_TildeExpansionInCLIFSRule(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	cliRules := config.CLIRules{
		FS:                  []string{"ro:~/mydir"},
		Net:                 nil,
		Syscall:             nil,
		Env:                 nil,
		Extends:             nil,
		NoConfig:            true,
		ConfigExplicitlySet: false,
	}
	cfg, err := config.Load("nonexistent.toml", cliRules, nil, "", "", "")
	require.NoError(t, err)
	require.Len(t, cfg.FSRules, 1)
	assert.Equal(t, filepath.Join(homeDir, "mydir"), cfg.FSRules[0].Path)
}

func TestLoad_SourcePathProvenance(t *testing.T) {
	cliRules := config.CLIRules{
		FS:                  []string{"ro:/usr/bin"},
		Net:                 []string{"http:example.com:443"},
		Syscall:             []string{"allow:ptrace"},
		Env:                 []string{"pass:HOME"},
		Extends:             nil,
		NoConfig:            true,
		ConfigExplicitlySet: false,
	}
	cfg, err := config.Load("nonexistent.toml", cliRules, nil, "", "", "")
	require.NoError(t, err)
	assert.Equal(t, config.SourceCLI, cfg.FSRules[0].SourcePath)
	assert.Equal(t, config.SourceCLI, cfg.NetRules[0].SourcePath)
	assert.Equal(t, config.SourceCLI, cfg.SyscallRules[0].SourcePath)
	assert.Equal(t, config.SourceCLI, cfg.EnvRules[0].SourcePath)
}

func TestLoad_InvalidCLIFSRuleRejected(t *testing.T) {
	cliRules := config.CLIRules{
		FS:                  []string{"badformat"},
		Net:                 nil,
		Syscall:             nil,
		Env:                 nil,
		Extends:             nil,
		NoConfig:            true,
		ConfigExplicitlySet: false,
	}
	_, err := config.Load("nonexistent.toml", cliRules, nil, "", "", "")
	assert.Error(t, err)
}

// TestRenderEffectiveTOML_CLIProvenance verifies that CLI-sourced rules show
// a "# <cli>" comment in the rendered output.
func TestRenderEffectiveTOML_CLIProvenance(t *testing.T) {
	t.Run("CLI-only shows cli provenance comment", func(t *testing.T) {
		cliRules := config.CLIRules{
			FS:                  []string{"ro:/usr/bin"},
			Net:                 nil,
			Syscall:             nil,
			Env:                 nil,
			Extends:             nil,
			NoConfig:            true,
			ConfigExplicitlySet: false,
		}
		cfg, err := config.Load("nonexistent.toml", cliRules, nil, "", "", "")
		require.NoError(t, err)

		rendered := config.RenderEffectiveTOML(cfg)
		assert.Contains(t, rendered, "# "+config.SourceCLI)
		assert.Contains(t, rendered, `"ro:/usr/bin"`)
	})

	t.Run("mixed config and CLI shows both provenance comments", func(t *testing.T) {
		cfgPath := writeTestConfig(t, `fs = ["ro:/etc"]`)
		cliRules := config.CLIRules{
			FS:                  []string{"ro:/usr/bin"},
			Net:                 nil,
			Syscall:             nil,
			Env:                 nil,
			Extends:             nil,
			NoConfig:            false,
			ConfigExplicitlySet: false,
		}
		cfg, err := config.Load(cfgPath, cliRules, nil, "", "", "")
		require.NoError(t, err)

		rendered := config.RenderEffectiveTOML(cfg)
		assert.Contains(t, rendered, "# "+cfgPath)
		assert.Contains(t, rendered, "# "+config.SourceCLI)
		assert.Contains(t, rendered, `"ro:/etc"`)
		assert.Contains(t, rendered, `"ro:/usr/bin"`)
	})
}
