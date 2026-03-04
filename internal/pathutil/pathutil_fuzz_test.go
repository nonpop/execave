package pathutil

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func FuzzExpandPath(f *testing.F) {
	// Seed corpus
	f.Add("/usr/bin", "/tmp")
	f.Add("./relative", "/home/user")
	f.Add("../parent", "/home/user/project")
	f.Add("/path/with/../dots", "/tmp")
	f.Add("/path//double//slash", "/tmp")
	f.Add("/path/./current", "/tmp")
	f.Add("", "/tmp")
	f.Add("/", "/tmp")
	f.Add("~/project", "/home/user")
	f.Add("~", "/home/user")
	f.Add("~foo", "/home/user")

	f.Fuzz(func(t *testing.T, path, baseDir string) {
		// Use absolute baseDir
		if !filepath.IsAbs(baseDir) {
			baseDir = "/fuzz" + baseDir
		}

		result, err := ExpandPath(path, baseDir)
		if err != nil {
			return // ~username or other error is fine
		}

		// Invariants for successful path expansion:

		// Result must be absolute (since baseDir is absolute)
		assert.True(t, filepath.IsAbs(result))

		// Result must be clean (idempotent under filepath.Clean)
		assert.Equal(t, filepath.Clean(result), result)

		// Expanding the result again must be idempotent (result is already absolute, no tilde)
		result2, err2 := ExpandPath(result, baseDir)
		require.NoError(t, err2)
		assert.Equal(t, result, result2)
	})
}
