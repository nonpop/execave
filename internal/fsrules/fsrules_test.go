package fsrules_test

import (
	"testing"

	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRule_Valid(t *testing.T) {
	tests := []struct {
		name         string
		rule         string
		expectedPerm fsrules.Permission
		expectedPath string
	}{
		{"read-write", "rw:/home/user", fsrules.PermissionReadWrite, "/home/user"},
		{"read-only", "ro:/usr/bin", fsrules.PermissionReadOnly, "/usr/bin"},
		{"none", "none:/secrets", fsrules.PermissionNone, "/secrets"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, err := fsrules.ParseRule(tt.rule, "/tmp")
			require.NoError(t, err)

			assert.Equal(t, tt.expectedPerm, rule.Permission)
			assert.Equal(t, tt.expectedPath, rule.Path)
			assert.Equal(t, fsrules.ResourceFS, rule.Resource)
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
			_, err := fsrules.ParseRule(tt.rule, "/tmp")
			assert.ErrorContains(t, err, "malformed rule")
		})
	}
}

func TestParseRule_InvalidPermission(t *testing.T) {
	_, err := fsrules.ParseRule("readonly:/path", "/tmp")
	assert.ErrorContains(t, err, "invalid permission type")
}

func TestNormalizePath_AbsolutePath(t *testing.T) {
	configDir := "/home/user/myproject"
	result := fsrules.NormalizePath("/home/user/../user/project/./src", configDir)
	assert.Equal(t, "/home/user/project/src", result)
}

func TestNormalizePath_TrailingSlash(t *testing.T) {
	configDir := "/home/user/myproject"
	result := fsrules.NormalizePath("/home/user/project/", configDir)
	assert.Equal(t, "/home/user/project", result)
}

func TestNormalizePath_RelativePath(t *testing.T) {
	configDir := "/home/user/myproject"
	result := fsrules.NormalizePath("./src", configDir)
	assert.Equal(t, "/home/user/myproject/src", result)
}

func TestNormalizePath_RelativeWithParent(t *testing.T) {
	configDir := "/home/user/myproject"
	result := fsrules.NormalizePath("../shared", configDir)
	assert.Equal(t, "/home/user/shared", result)
}

func TestNormalizePath_TrulyRelative(t *testing.T) {
	configDir := "/home/user/myproject"
	result := fsrules.NormalizePath("src", configDir)
	assert.Equal(t, "/home/user/myproject/src", result)
}

func TestNormalizePath_CurrentDir(t *testing.T) {
	configDir := "/home/user/myproject"
	result := fsrules.NormalizePath(".", configDir)
	assert.Equal(t, "/home/user/myproject", result)
}

func TestNormalizePath_TildeNotExpanded(t *testing.T) {
	// Tilde is not expanded - it's treated as a literal directory name.
	// This documents current behavior; tilde expansion may be added later.
	configDir := "/home/user/myproject"
	result := fsrules.NormalizePath("~/project", configDir)
	assert.Equal(t, "/home/user/myproject/~/project", result)
}

func TestNormalizePath_EmptyPath(t *testing.T) {
	configDir := "/home/user/myproject"
	result := fsrules.NormalizePath("", configDir)
	assert.Equal(t, "/home/user/myproject", result)
}

func TestNormalizePath_RootPath(t *testing.T) {
	configDir := "/home/user/myproject"
	result := fsrules.NormalizePath("/", configDir)
	assert.Equal(t, "/", result)
}

func TestNormalizePath_MultipleSlashes(t *testing.T) {
	configDir := "/home/user/myproject"
	result := fsrules.NormalizePath("/home//user///project", configDir)
	assert.Equal(t, "/home/user/project", result)
}

func TestNormalizePath_ParentTraversalBeyondRoot(t *testing.T) {
	// Traversing beyond root stops at root.
	configDir := "/home/user"
	result := fsrules.NormalizePath("../../../..", configDir)
	assert.Equal(t, "/", result)
}
