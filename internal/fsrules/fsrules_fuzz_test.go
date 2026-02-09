package fsrules_test

import (
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
)

func FuzzParseRule(f *testing.F) {
	// Seed corpus with valid rules
	f.Add("ro:/usr/bin", "/config")
	f.Add("rw:/home/user", "/config")
	f.Add("none:/secret", "/config")
	f.Add("ro:./relative", "/config")
	f.Add("rw:../parent", "/config")

	// Seed with invalid rules
	f.Add("ro", "/config")
	f.Add("invalid", "/config")
	f.Add(":", "/config")
	f.Add("", "/config")
	f.Add("invalid:/path", "/config")

	f.Fuzz(func(t *testing.T, ruleStr, configDir string) {
		// Use absolute configDir to test path resolution properly
		if !filepath.IsAbs(configDir) {
			configDir = "/fuzz" + configDir
		}

		rule, err := fsrules.ParseRule(ruleStr, configDir)
		if err != nil {
			return // Invalid input is fine
		}

		// Invariants for successfully parsed rules:

		// Resource must be valid
		assert.NotEqual(t, fsrules.ResourceUnknown, rule.Resource)

		// Permission must be valid
		assert.NotEqual(t, fsrules.PermissionUnknown, rule.Permission)

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

	f.Fuzz(func(t *testing.T, path, configDir string) {
		// Use absolute configDir
		if !filepath.IsAbs(configDir) {
			configDir = "/fuzz" + configDir
		}

		result := fsrules.NormalizePath(path, configDir)

		// Invariants for path normalization:

		// Result must be absolute (since configDir is absolute)
		assert.True(t, filepath.IsAbs(result))

		// Result must be clean (idempotent under filepath.Clean)
		assert.Equal(t, filepath.Clean(result), result)

		// Normalizing the result again must be idempotent
		assert.Equal(t, result, fsrules.NormalizePath(result, configDir))
	})
}
