package fsrules

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func FuzzParseRule(f *testing.F) {
	// Seed corpus with valid rules
	f.Add("ro:/usr/bin", "/config")
	f.Add("rw:/home/user", "/config")
	f.Add("none:/secret", "/config")
	f.Add("ro:./relative", "/config")
	f.Add("rw:../parent", "/config")
	f.Add("rw:~/project", "/config")
	f.Add("ro:~", "/config")

	// Seed with invalid rules
	f.Add("ro", "/config")
	f.Add("invalid", "/config")
	f.Add(":", "/config")
	f.Add("", "/config")
	f.Add("invalid:/path", "/config")
	f.Add("ro:~username/data", "/config")

	f.Fuzz(func(t *testing.T, ruleStr, configDir string) {
		// Use absolute configDir to test path resolution properly
		if !filepath.IsAbs(configDir) {
			configDir = "/fuzz" + configDir
		}

		rule, err := ParseAccessRule(ruleStr, configDir)
		if err != nil {
			return // Invalid input is fine
		}

		// Invariants for successfully parsed rules:

		// Permission must be valid
		assert.NotEqual(t, PermissionUnknown, rule.Permission)

		// Path must not be empty
		assert.NotEmpty(t, rule.Path)

		// Path must be absolute (since configDir is absolute)
		assert.True(t, filepath.IsAbs(rule.Path))

		// Path must be clean
		assert.Equal(t, filepath.Clean(rule.Path), rule.Path)

		// RawRule must be preserved
		assert.Equal(t, ruleStr, rule.RawRule)
	})
}

func FuzzNormalizePath(f *testing.F) {
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

	f.Fuzz(func(t *testing.T, path, configDir string) {
		// Use absolute configDir
		if !filepath.IsAbs(configDir) {
			configDir = "/fuzz" + configDir
		}

		result, err := normalizePath(path, configDir)
		if err != nil {
			return // ~username or other error is fine
		}

		// Invariants for successful path normalization:

		// Result must be absolute (since configDir is absolute)
		assert.True(t, filepath.IsAbs(result))

		// Result must be clean (idempotent under filepath.Clean)
		assert.Equal(t, filepath.Clean(result), result)

		// Normalizing the result again must be idempotent (result is already absolute, no tilde)
		result2, err2 := normalizePath(result, configDir)
		require.NoError(t, err2)
		assert.Equal(t, result, result2)
	})
}
