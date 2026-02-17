package fsrules

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRule_Valid(t *testing.T) {
	tests := []struct {
		name         string
		rule         string
		expectedPerm Permission
		expectedPath string
	}{
		{"read-write", "rw:/home/user", PermissionReadWrite, "/home/user"},
		{"read-only", "ro:/usr/bin", PermissionReadOnly, "/usr/bin"},
		{"none", "none:/secrets", PermissionNone, "/secrets"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := Parse(tt.rule, "/tmp")
			require.NoError(t, err)

			assert.Equal(t, tt.expectedPerm, rule.Permission)
			assert.Equal(t, tt.expectedPath, rule.Path)
		})
	}
}

func TestParseRule_InvalidFormat(t *testing.T) {
	tests := []struct {
		name string
		rule string
	}{
		{"missing-path", "ro"},
		{"no-colons", "invalid"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.rule, "/tmp")
			assert.ErrorContains(t, err, "malformed rule")
		})
	}
}

func TestParseRule_InvalidPermission(t *testing.T) {
	_, err := Parse("readonly:/path", "/tmp")
	assert.ErrorContains(t, err, "invalid permission type")
}

func TestNormalizePath_AbsolutePath(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := normalizePath("/home/user/../user/project/./src", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/project/src", result)
}

func TestNormalizePath_TrailingSlash(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := normalizePath("/home/user/project/", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/project", result)
}

func TestNormalizePath_RelativePath(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := normalizePath("./src", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject/src", result)
}

func TestNormalizePath_RelativeWithParent(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := normalizePath("../shared", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/shared", result)
}

func TestNormalizePath_TrulyRelative(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := normalizePath("src", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject/src", result)
}

func TestNormalizePath_CurrentDir(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := normalizePath(".", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject", result)
}

func TestNormalizePath_TildeSlashExpanded(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	result, err := normalizePath("~/project", "/")
	require.NoError(t, err)
	assert.Equal(t, homeDir+"/project", result)
}

func TestNormalizePath_BareTildeExpanded(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	result, err := normalizePath("~", "/")
	require.NoError(t, err)
	assert.Equal(t, homeDir, result)
}

func TestNormalizePath_TildePathCleaned(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	result, err := normalizePath("~/project/../other", "/")
	require.NoError(t, err)
	assert.Equal(t, homeDir+"/other", result)
}

func TestNormalizePath_TildeUsernameRejected(t *testing.T) {
	_, err := normalizePath("~otheruser/data", "/home/user")
	require.Error(t, err)
	assert.True(t,
		strings.Contains(err.Error(), "~username") || strings.Contains(err.Error(), "not supported"))
}

func TestNormalizePath_EmptyPath(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := normalizePath("", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject", result)
}

func TestNormalizePath_RootPath(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := normalizePath("/", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/", result)
}

func TestNormalizePath_MultipleSlashes(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := normalizePath("/home//user///project", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/project", result)
}

func TestNormalizePath_ParentTraversalBeyondRoot(t *testing.T) {
	// Traversing beyond root stops at root.
	configDir := "/home/user"
	result, err := normalizePath("../../../..", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/", result)
}
