package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/stretchr/testify/assert"
)

func FuzzLoad(f *testing.F) {
	// Seed corpus with valid examples
	f.Add(`{"rules": []}`)
	f.Add(`{"rules": ["fs:ro:/usr/bin"]}`)
	f.Add(`{"rules": ["fs:rw:/home", "fs:ro:/etc"]}`)
	f.Add(`{"rules": ["fs:none:/secret"]}`)
	f.Add(`{"rules": ["fs:ro:./relative"]}`)
	f.Add(`{"rules": ["fs:rw:/path/with/../dots"]}`)

	// Seed with some invalid examples
	f.Add(`{"rules": ["invalid"]}`)
	f.Add(`{"rules": [123]}`)
	f.Add(`{"rules": "not an array"}`)
	f.Add(`{invalid json}`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, configJSON string) {
		// Create temporary config file
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "fuzz.json")

		if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
			t.Skip("failed to write config file")
		}

		cfg, err := config.Load(configPath, nil)
		if err != nil {
			return // Invalid input is fine
		}

		// Invariants that must hold for any successfully loaded config:
		seenPaths := make(map[string]bool)
		for _, rule := range cfg.Rules {
			// Resource must be valid (not Unknown)
			assert.NotEqual(t, config.ResourceUnknown, rule.Resource)

			// Permission must be valid (not Unknown)
			assert.NotEqual(t, config.PermissionUnknown, rule.Permission)

			// Path must not be empty
			assert.NotEmpty(t, rule.Path)

			// Path must be absolute (config is in tmpDir which is absolute)
			assert.True(t, filepath.IsAbs(rule.Path))

			// Path must be clean (no redundant . or ..)
			assert.Equal(t, filepath.Clean(rule.Path), rule.Path)

			// No duplicate paths (should be caught by validation, but verify)
			assert.False(t, seenPaths[rule.Path])
			seenPaths[rule.Path] = true
		}
	})
}

func FuzzParseRule(f *testing.F) {
	// Seed corpus with valid rules
	f.Add("fs:ro:/usr/bin", "/config")
	f.Add("fs:rw:/home/user", "/config")
	f.Add("fs:none:/secret", "/config")
	f.Add("fs:ro:./relative", "/config")
	f.Add("fs:rw:../parent", "/config")

	// Seed with invalid rules
	f.Add("fs:ro", "/config")
	f.Add("fs:/path", "/config")
	f.Add("invalid", "/config")
	f.Add(":", "/config")
	f.Add("", "/config")
	f.Add("fs:invalid:/path", "/config")
	f.Add("net:allow:443", "/config")

	f.Fuzz(func(t *testing.T, ruleStr, configDir string) {
		// Use absolute configDir to test path resolution properly
		if !filepath.IsAbs(configDir) {
			configDir = "/fuzz" + configDir
		}

		rule, err := config.ParseRule(ruleStr, configDir)
		if err != nil {
			return // Invalid input is fine
		}

		// Invariants for successfully parsed rules:

		// Resource must be valid
		assert.NotEqual(t, config.ResourceUnknown, rule.Resource)

		// Permission must be valid
		assert.NotEqual(t, config.PermissionUnknown, rule.Permission)

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

		result := config.NormalizePath(path, configDir)

		// Invariants for path normalization:

		// Result must be absolute (since configDir is absolute)
		assert.True(t, filepath.IsAbs(result))

		// Result must be clean (idempotent under filepath.Clean)
		assert.Equal(t, filepath.Clean(result), result)

		// Normalizing the result again must be idempotent
		assert.Equal(t, result, config.NormalizePath(result, configDir))
	})
}
