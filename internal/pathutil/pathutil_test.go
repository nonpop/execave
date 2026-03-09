package pathutil

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandPath_AbsolutePath(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := ExpandPath("/home/user/../user/project/./src", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/project/src", result)
}

func TestExpandPath_TrailingSlash(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := ExpandPath("/home/user/project/", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/project", result)
}

func TestExpandPath_RelativePath(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := ExpandPath("./src", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject/src", result)
}

func TestExpandPath_RelativeWithParent(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := ExpandPath("../shared", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/shared", result)
}

func TestExpandPath_TrulyRelative(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := ExpandPath("src", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject/src", result)
}

func TestExpandPath_CurrentDir(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := ExpandPath(".", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject", result)
}

func TestExpandPath_TildeSlashExpanded(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	result, err := ExpandPath("~/project", "/")
	require.NoError(t, err)
	assert.Equal(t, homeDir+"/project", result)
}

func TestExpandPath_BareTildeExpanded(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	result, err := ExpandPath("~", "/")
	require.NoError(t, err)
	assert.Equal(t, homeDir, result)
}

func TestExpandPath_TildePathCleaned(t *testing.T) {
	homeDir, err := os.UserHomeDir()
	require.NoError(t, err)

	result, err := ExpandPath("~/project/../other", "/")
	require.NoError(t, err)
	assert.Equal(t, homeDir+"/other", result)
}

func TestExpandPath_EmptyPath(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := ExpandPath("", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/myproject", result)
}

func TestExpandPath_RootPath(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := ExpandPath("/", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/", result)
}

func TestExpandPath_MultipleSlashes(t *testing.T) {
	configDir := "/home/user/myproject"
	result, err := ExpandPath("/home//user///project", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/home/user/project", result)
}

func TestExpandPath_ParentTraversalBeyondRoot(t *testing.T) {
	// Traversing beyond root stops at root.
	configDir := "/home/user"
	result, err := ExpandPath("../../../..", configDir)
	require.NoError(t, err)
	assert.Equal(t, "/", result)
}

func TestShortenPath_PathUnderBothConfigDirTakesPriority(t *testing.T) {
	result := ShortenPath("/home/user/project/src/main.go", "/home/user", "/home/user/project")
	assert.Equal(t, "src/main.go", result)
}

func TestShortenPath_PathOutsideHomeDirShownAsAbsolute(t *testing.T) {
	result := ShortenPath("/usr/lib/libc.so", "/home/user", "/home/user/project")
	assert.Equal(t, "/usr/lib/libc.so", result)
}

func TestShortenPath_PathEqualToConfigDirShortenedToDot(t *testing.T) {
	result := ShortenPath("/home/user/project", "/home/user", "/home/user/project")
	assert.Equal(t, ".", result)
}

func TestShortenPath_EmptyHomeDirDisablesTildeShortening(t *testing.T) {
	result := ShortenPath("/home/user/.ssh/id_rsa", "", "/home/user/project")
	assert.Equal(t, "/home/user/.ssh/id_rsa", result)
}

func TestShortenPath_PathEqualToHomeDir(t *testing.T) {
	result := ShortenPath("/home/user", "/home/user", "/home/user/project")
	assert.Equal(t, "~", result)
}

func TestShortenPath_EmptyConfigDirUsesAbsoluteOrTilde(t *testing.T) {
	result := ShortenPath("/home/user/project/src/main.go", "/home/user", "")
	assert.Equal(t, "~/project/src/main.go", result)
}

func TestShortenPath_BothEmptyReturnsAbsolute(t *testing.T) {
	result := ShortenPath("/home/user/project/src/main.go", "", "")
	assert.Equal(t, "/home/user/project/src/main.go", result)
}
