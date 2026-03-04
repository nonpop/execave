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

// --- Requirement: Config file location ---
// Note: "Default config location" and "Custom config location" test CLI flag routing,
// not the config package. config.Load always receives an explicit path from the caller.

func TestIntegration_ConfigFileLocation_ConfigFileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/config.toml", nil, "", "", "")

	require.Error(t, err)
	assert.ErrorContains(t, err, "file not found")
}

// --- Requirement: Config file format ---

func TestIntegration_ConfigFileFormat_ValidConfigWithFsAndNetRules(t *testing.T) {
	cfg, err := loadTestConfig(t, `fs = ["ro:/usr/bin"]
net = ["http:api.anthropic.com:443"]`)

	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
	assert.Len(t, cfg.NetRules, 1)
}

func TestIntegration_ConfigFileFormat_EmptyRulesArray(t *testing.T) {
	cfg, err := loadTestConfig(t, ``)

	require.NoError(t, err)
	assert.Empty(t, cfg.FSRules)
	assert.Empty(t, cfg.NetRules)
}

func TestIntegration_ConfigFileFormat_UnknownResourceType(t *testing.T) {
	_, err := loadTestConfig(t, `fs = ["ro:/usr/bin"]
net = ["dns:allow:example.com"]`)

	assert.ErrorContains(t, err, "invalid action")
}

func TestIntegration_ConfigFileFormat_InvalidRuleRejectedAtConfigLoad(t *testing.T) {
	_, err := loadTestConfig(t, `net = ["http:example.com"]`)

	assert.ErrorContains(t, err, "malformed rule")
}

func TestIntegration_ConfigFileFormat_ConfigWithComments(t *testing.T) {
	content := `# Sandbox for my coding agent
fs = [
    # Project directory: read-only
    "ro:/usr/bin",  # inline comment
]
net = ["http:api.anthropic.com:443"]`

	cfg, err := loadTestConfig(t, content)

	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
	assert.Len(t, cfg.NetRules, 1)
}

func TestIntegration_ConfigFileFormat_ConfigWithTrailingComma(t *testing.T) {
	cfg, err := loadTestConfig(t, `fs = ["ro:/usr/bin",]`)

	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
}

func TestIntegration_RenderEffectiveTOML_SyscallRuleSourceCommentReflectsOriginatingConfig(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.toml")
	rootPath := filepath.Join(dir, "execave.toml")

	require.NoError(t, os.WriteFile(basePath, []byte(`syscall = ["allow:ptrace"]`), 0o600))
	require.NoError(t, os.WriteFile(rootPath, []byte("extends = [\"base.toml\"]\nsyscall = [\"allow:reboot\"]"), 0o600))

	cfg, err := config.Load(rootPath, nil, "", "", "")
	require.NoError(t, err)

	rendered := config.RenderEffectiveTOML(cfg)

	assert.Contains(t, rendered, "  # "+basePath+"\n  \"allow:ptrace\",")
	assert.Contains(t, rendered, "  # "+rootPath+"\n  \"allow:reboot\",")
}

func TestIntegration_LoadGeneratesSyntheticReadOnlyRuleForWritableConfigPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "execave.toml")
	content := `fs = ["rw:` + dir + `"]`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0o600))

	cfg, err := config.Load(configPath, nil, "", "", "")
	require.NoError(t, err)

	require.Len(t, cfg.FSRules, 2)
	synthetic := cfg.FSRules[1]
	assert.Equal(t, fsrules.PermissionReadOnly, synthetic.Permission)
	assert.Equal(t, configPath, synthetic.Path)
	assert.Equal(t, "ro:"+configPath, synthetic.RawRule)
	assert.Equal(t, "", synthetic.SourcePath)
}

func TestIntegration_LoadNoSyntheticRuleForReadOnlyConfigPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "execave.toml")
	content := `fs = ["ro:` + dir + `"]`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0o600))

	cfg, err := config.Load(configPath, nil, "", "", "")
	require.NoError(t, err)

	assert.Len(t, cfg.FSRules, 1)
}

func TestIntegration_RenderEffectiveTOML_SyntheticRulesLabeledSynthetic(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "execave.toml")
	content := `fs = ["rw:` + dir + `"]`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0o600))

	cfg, err := config.Load(configPath, nil, "", "", "")
	require.NoError(t, err)

	rendered := config.RenderEffectiveTOML(cfg)

	assert.Contains(t, rendered, "  # <synthetic>\n  \"ro:"+configPath+"\",")
}

func TestIntegration_RenderEffectiveTOML_TypedSectionsAndSourceComments(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "base.toml")
	rootPath := filepath.Join(dir, "execave.toml")

	baseContent := `fs = ["ro:/usr"]
net = ["http:api.example.com:443"]
syscall = ["allow:ptrace"]`
	rootContent := `extends = ["base.toml"]
fs = ["rw:./workspace"]
net = ["none:blocked.example.com:443"]
syscall = ["allow:reboot"]`

	require.NoError(t, os.WriteFile(basePath, []byte(baseContent), 0o600))
	require.NoError(t, os.WriteFile(rootPath, []byte(rootContent), 0o600))

	cfg, err := config.Load(rootPath, nil, "", "", "")
	require.NoError(t, err)

	rendered := config.RenderEffectiveTOML(cfg)

	assert.Contains(t, rendered, "fs = [")
	assert.Contains(t, rendered, "net = [")
	assert.Contains(t, rendered, "syscall = [")
	assert.Contains(t, rendered, "  # "+basePath+"\n  \"ro:/usr\",")
	assert.Contains(t, rendered, "  # "+basePath+"\n  \"ro:/usr\",\n\n  # "+rootPath+"\n  \"rw:"+filepath.Join(dir, "workspace")+"\",")
	assert.Contains(t, rendered, "\"http:api.example.com:443\",")
	assert.Contains(t, rendered, "\"none:blocked.example.com:443\",")
	assert.Contains(t, rendered, "\"allow:ptrace\",")
	assert.Contains(t, rendered, "\"allow:reboot\",")
}
