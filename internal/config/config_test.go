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
	return config.Load(configPath, nil) //nolint:wrapcheck
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

func TestLoad_ValidConfig(t *testing.T) {
	cfg, err := loadTestConfig(t, `rules = [
	"fs:ro:/usr/bin",
	"fs:rw:/home/user/project",
]`)
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 2)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/path/execave.toml", nil)
	assert.ErrorContains(t, err, "config file not found")
}

func TestLoad_InvalidTOML(t *testing.T) {
	_, err := loadTestConfig(t, "invalid toml [[[")
	assert.ErrorContains(t, err, "parse config")
}

func TestLoad_UnknownResourceType(t *testing.T) {
	_, err := loadTestConfig(t, `rules = ["dns:allow:example.com"]`)
	assert.ErrorContains(t, err, "unknown resource type")
}

func TestLoad_ValidNetRule(t *testing.T) {
	cfg, err := loadTestConfig(t, `rules = [
	"fs:ro:/usr/bin",
	"net:https:api.anthropic.com:443",
]`)
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 1)
	assert.Len(t, cfg.NetRules, 1)
}

func TestLoad_HasNetRules(t *testing.T) {
	cfg, err := loadTestConfig(t, `rules = ["net:https:api.anthropic.com:443"]`)
	require.NoError(t, err)
	assert.True(t, cfg.HasNetRules())
}

func TestLoad_HasNoNetRules(t *testing.T) {
	cfg, err := loadTestConfig(t, `rules = ["fs:ro:/usr/bin"]`)
	require.NoError(t, err)
	assert.False(t, cfg.HasNetRules())
}

func TestLoad_InvalidNetRule(t *testing.T) {
	_, err := loadTestConfig(t, `rules = ["net:https:example.com"]`)
	assert.ErrorContains(t, err, "malformed rule")
}

func TestLoad_NetRuleDuplicateIdentityRejected(t *testing.T) {
	_, err := loadTestConfig(t, `rules = [
	"net:https:example.com:443",
	"net:none:example.com:443",
]`)
	assert.ErrorContains(t, err, "duplicate net rule")
}

func TestLoad_NetRuleMixedPortPatternsRejected(t *testing.T) {
	_, err := loadTestConfig(t, `rules = [
	"net:https:example.com:*",
	"net:none:example.com:443",
]`)
	assert.ErrorContains(t, err, "mixed port patterns")
}

func TestValidate_NoneWithChildAllowed(t *testing.T) {
	cfg, err := loadTestConfig(t, `rules = [
	"fs:none:/home/user/project/.env",
	"fs:ro:/home/user/project/.env/example",
]`)
	require.NoError(t, err)
	assert.Len(t, cfg.FSRules, 2)
}

func TestValidate_NoneTerminalValid(t *testing.T) {
	_, err := loadTestConfig(t, `rules = [
	"fs:rw:/home/user/project",
	"fs:none:/home/user/project/.env",
]`)
	assert.NoError(t, err)
}

func TestDuplicatePaths_DifferentPermissions_Rejected(t *testing.T) {
	_, err := loadTestConfig(t, `rules = [
	"fs:ro:/home/user",
	"fs:rw:/home/user",
]`)
	require.ErrorContains(t, err, "duplicate path")
	assert.ErrorContains(t, err, "/home/user")
}

func TestDuplicatePaths_IdenticalRules_Rejected(t *testing.T) {
	_, err := loadTestConfig(t, `rules = [
	"fs:ro:/path",
	"fs:ro:/path",
]`)
	require.ErrorContains(t, err, "duplicate path")
	assert.ErrorContains(t, err, "/path")
}

func TestDuplicatePaths_TrailingSlash_Rejected(t *testing.T) {
	_, err := loadTestConfig(t, `rules = [
	"fs:ro:/foo",
	"fs:ro:/foo/",
]`)
	require.ErrorContains(t, err, "duplicate path")
	assert.ErrorContains(t, err, "/foo")
}

func TestPermission_Strictness(t *testing.T) {
	assert.Greater(t, fsrules.PermissionNone, fsrules.PermissionReadOnly)
	assert.Greater(t, fsrules.PermissionReadOnly, fsrules.PermissionReadWrite)
}

func TestValidate_ConfigFileExplicitlyWritable_Rejected(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "execave.toml")

	// Config that makes itself writable
	content := `rules = ["fs:rw:` + configPath + `"]`
	err := os.WriteFile(configPath, []byte(content), 0o600)
	require.NoError(t, err)

	_, err = config.Load(configPath, nil)
	require.ErrorContains(t, err, "config file must not be writable")
}

func TestValidate_ManagedPath_Rejected(t *testing.T) {
	managedPaths := []string{"/proc", "/dev", "/tmp"}

	tests := []struct {
		name    string
		rule    string
		wantErr string
	}{
		{"exact match", `"fs:ro:/proc"`, "/proc"},
		{"subpath", `"fs:rw:/proc/self/status"`, "/proc"},
		{"different managed", `"fs:ro:/dev/null"`, "/dev"},
		{"tmp subpath", `"fs:rw:/tmp/foo"`, "/tmp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := `rules = [` + tt.rule + `]`
			configPath := writeTestConfig(t, content)

			_, err := config.Load(configPath, managedPaths)
			require.ErrorContains(t, err, "managed path")
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestValidate_ManagedPath_SimilarNameAllowed(t *testing.T) {
	managedPaths := []string{"/proc", "/dev", "/tmp"}

	// Paths that look similar but aren't under managed dirs
	tests := []struct {
		name string
		rule string
	}{
		{"proc in name", `"fs:ro:/home/user/proc"`},
		{"procfile", `"fs:ro:/home/user/procfile"`},
		{"dev in project", `"fs:rw:/home/user/dev"`},
		{"tmpdir", `"fs:rw:/home/user/tmpdir"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := `rules = [` + tt.rule + `]`
			configPath := writeTestConfig(t, content)

			_, err := config.Load(configPath, managedPaths)
			assert.NoError(t, err)
		})
	}
}
