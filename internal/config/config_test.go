package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/config"
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
	configPath := filepath.Join(tmpDir, "execave.json")
	err := os.WriteFile(configPath, []byte(content), 0o600)
	require.NoError(t, err)
	return configPath
}

func TestLoad_ValidConfig(t *testing.T) {
	cfg, err := loadTestConfig(t, `{
		"rules": [
			"fs:ro:/usr/bin",
			"fs:rw:/home/user/project"
		]
	}`)
	require.NoError(t, err)
	assert.Len(t, cfg.Rules, 2)
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/path/execave.json", nil)
	assert.ErrorContains(t, err, "config file not found")
}

func TestLoad_InvalidJSON(t *testing.T) {
	_, err := loadTestConfig(t, "{invalid json}")
	assert.ErrorContains(t, err, "parse config")
}

func TestParseRule_Valid(t *testing.T) {
	tests := []struct {
		name             string
		rule             string
		expectedPerm     config.Permission
		expectedPath     string
		expectedResource config.Resource
	}{
		{"read-write", "fs:rw:/home/user", config.PermissionReadWrite, "/home/user", config.ResourceFS},
		{"read-only", "fs:ro:/usr/bin", config.PermissionReadOnly, "/usr/bin", config.ResourceFS},
		{"none", "fs:none:/secrets", config.PermissionNone, "/secrets", config.ResourceFS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := config.ParseRule(tt.rule, "/tmp")
			require.NoError(t, err)

			assert.Equal(t, tt.expectedPerm, rule.Permission)
			assert.Equal(t, tt.expectedPath, rule.Path)
			assert.Equal(t, tt.expectedResource, rule.Resource)
		})
	}
}

func TestParseRule_InvalidFormat(t *testing.T) {
	tests := []struct {
		name string
		rule string
	}{
		{"missing-path", "fs:ro"},
		{"missing-permission", "fs:/path"},
		{"no-colons", "invalid"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.ParseRule(tt.rule, "/tmp")
			assert.ErrorContains(t, err, "malformed rule")
		})
	}
}

func TestParseRule_InvalidPermission(t *testing.T) {
	_, err := config.ParseRule("fs:readonly:/path", "/tmp")
	assert.ErrorContains(t, err, "invalid permission type")
}

func TestParseRule_InvalidResource(t *testing.T) {
	_, err := config.ParseRule("net:allow:443", "/tmp")
	assert.ErrorContains(t, err, "unknown resource type")
}

func TestNormalizePath_AbsolutePath(t *testing.T) {
	configDir := "/home/user/myproject"
	result := config.NormalizePath("/home/user/../user/project/./src", configDir)
	assert.Equal(t, "/home/user/project/src", result)
}

func TestNormalizePath_TrailingSlash(t *testing.T) {
	configDir := "/home/user/myproject"
	result := config.NormalizePath("/home/user/project/", configDir)
	assert.Equal(t, "/home/user/project", result)
}

func TestNormalizePath_RelativePath(t *testing.T) {
	configDir := "/home/user/myproject"
	result := config.NormalizePath("./src", configDir)
	assert.Equal(t, "/home/user/myproject/src", result)
}

func TestNormalizePath_RelativeWithParent(t *testing.T) {
	configDir := "/home/user/myproject"
	result := config.NormalizePath("../shared", configDir)
	assert.Equal(t, "/home/user/shared", result)
}

func TestNormalizePath_TrulyRelative(t *testing.T) {
	configDir := "/home/user/myproject"
	result := config.NormalizePath("src", configDir)
	assert.Equal(t, "/home/user/myproject/src", result)
}

func TestNormalizePath_CurrentDir(t *testing.T) {
	configDir := "/home/user/myproject"
	result := config.NormalizePath(".", configDir)
	assert.Equal(t, "/home/user/myproject", result)
}

func TestNormalizePath_TildeNotExpanded(t *testing.T) {
	// Tilde is not expanded - it's treated as a literal directory name.
	// This documents current behavior; tilde expansion may be added later.
	configDir := "/home/user/myproject"
	result := config.NormalizePath("~/project", configDir)
	assert.Equal(t, "/home/user/myproject/~/project", result)
}

func TestNormalizePath_EmptyPath(t *testing.T) {
	configDir := "/home/user/myproject"
	result := config.NormalizePath("", configDir)
	assert.Equal(t, "/home/user/myproject", result)
}

func TestNormalizePath_RootPath(t *testing.T) {
	configDir := "/home/user/myproject"
	result := config.NormalizePath("/", configDir)
	assert.Equal(t, "/", result)
}

func TestNormalizePath_MultipleSlashes(t *testing.T) {
	configDir := "/home/user/myproject"
	result := config.NormalizePath("/home//user///project", configDir)
	assert.Equal(t, "/home/user/project", result)
}

func TestNormalizePath_ParentTraversalBeyondRoot(t *testing.T) {
	// Traversing beyond root stops at root.
	configDir := "/home/user"
	result := config.NormalizePath("../../../..", configDir)
	assert.Equal(t, "/", result)
}

func TestValidate_NoneWithChildAllowed(t *testing.T) {
	cfg, err := loadTestConfig(t, `{
		"rules": [
			"fs:none:/home/user/project/.env",
			"fs:ro:/home/user/project/.env/example"
		]
	}`)
	require.NoError(t, err)
	assert.Len(t, cfg.Rules, 2)
}

func TestValidate_NoneTerminalValid(t *testing.T) {
	_, err := loadTestConfig(t, `{
		"rules": [
			"fs:rw:/home/user/project",
			"fs:none:/home/user/project/.env"
		]
	}`)
	assert.NoError(t, err)
}

func TestDuplicatePaths_DifferentPermissions_Rejected(t *testing.T) {
	_, err := loadTestConfig(t, `{
		"rules": [
			"fs:ro:/home/user",
			"fs:rw:/home/user"
		]
	}`)
	require.ErrorContains(t, err, "duplicate path")
	assert.ErrorContains(t, err, "/home/user")
}

func TestDuplicatePaths_IdenticalRules_Rejected(t *testing.T) {
	_, err := loadTestConfig(t, `{
		"rules": [
			"fs:ro:/path",
			"fs:ro:/path"
		]
	}`)
	require.ErrorContains(t, err, "duplicate path")
	assert.ErrorContains(t, err, "/path")
}

func TestDuplicatePaths_TrailingSlash_Rejected(t *testing.T) {
	_, err := loadTestConfig(t, `{
		"rules": [
			"fs:ro:/foo",
			"fs:ro:/foo/"
		]
	}`)
	require.ErrorContains(t, err, "duplicate path")
	assert.ErrorContains(t, err, "/foo")
}

func TestPermission_Strictness(t *testing.T) {
	assert.Greater(t, config.PermissionNone, config.PermissionReadOnly)
	assert.Greater(t, config.PermissionReadOnly, config.PermissionReadWrite)
}

func TestValidate_ConfigFileExplicitlyWritable_Rejected(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "execave.json")

	// Config that makes itself writable
	content := `{
		"rules": [
			"fs:rw:` + configPath + `"
		]
	}`
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
			content := `{"rules": [` + tt.rule + `]}`
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
			content := `{"rules": [` + tt.rule + `]}`
			configPath := writeTestConfig(t, content)

			_, err := config.Load(configPath, managedPaths)
			assert.NoError(t, err)
		})
	}
}
