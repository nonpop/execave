package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nonpop/execave/internal/config"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/stretchr/testify/assert"
)

func FuzzLoad(f *testing.F) {
	// Seed corpus with valid TOML examples
	f.Add(``)
	f.Add(`fs = ["ro:/usr/bin"]`)
	f.Add(`fs = ["rw:/home", "ro:/etc"]`)
	f.Add(`fs = ["none:/secret"]`)
	f.Add(`fs = ["ro:./relative"]`)
	f.Add(`fs = ["rw:/path/with/../dots"]`)

	// Seed with syscall rules
	f.Add(`syscall = ["allow:ptrace"]`)
	f.Add(`syscall = ["nolog:bpf"]`)

	// Seed with some invalid examples
	f.Add(`fs = ["invalid"]`)
	f.Add(`{invalid json}`)
	f.Add(`invalid toml [[[`)
	f.Add(`fs = []
net = []
syscall = []`)

	f.Fuzz(func(t *testing.T, configTOML string) {
		// Create temporary config file
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "fuzz.toml")

		if err := os.WriteFile(configPath, []byte(configTOML), 0o600); err != nil {
			t.Fatal("failed to write config file")
		}

		cfg, err := config.Load(configPath, nil)
		if err != nil {
			return // Invalid input is fine
		}

		// Invariants that must hold for any successfully loaded config:
		seenPaths := make(map[string]bool)
		for _, rule := range cfg.FSRules {
			// Permission must be valid (not Unknown)
			assert.NotEqual(t, fsrules.PermissionUnknown, rule.Permission)

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
