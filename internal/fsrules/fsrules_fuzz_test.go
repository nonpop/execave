package fsrules

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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

		rule, err := ParseRule(ruleStr, configDir, "")
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
