package logfilter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShortenPath_PathUnderConfigDirShortenedToRelative(t *testing.T) {
	result := ShortenPath("/home/user/project/src/main.go", "/home/user", "/home/user/project")
	assert.Equal(t, "src/main.go", result)
}

func TestShortenPath_PathUnderHomeDirButOutsideConfigDirShortenedToTilde(t *testing.T) {
	result := ShortenPath("/home/user/.ssh/id_rsa", "/home/user", "/home/user/project")
	assert.Equal(t, "~/.ssh/id_rsa", result)
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
