package fsrules

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func FuzzMatchesPath(f *testing.F) {
	// Seed corpus with typical scenarios
	f.Add("/home/user", "/home/user/file.txt")
	f.Add("/home/user", "/home/user")
	f.Add("/home/user", "/home/username")
	f.Add("/etc/passwd", "/etc/passwd")
	f.Add("/etc/passwd", "/etc/passwd/child")
	f.Add("/home/user/project", "/home/user/project/src/main.go")
	f.Add("/", "/any/path")
	f.Add("", "")

	// Edge cases
	f.Add("/path", "/path/")
	f.Add("/path/", "/path")
	f.Add("/home/user", "/home/user2")

	f.Fuzz(func(t *testing.T, rulePath string, targetPath string) {
		// Normalize inputs like the real code does
		cleanRulePath := filepath.Clean(rulePath)
		cleanTargetPath := filepath.Clean(targetPath)

		result := matchesPath(cleanRulePath, cleanTargetPath)

		// Invariant 1: Exact match always succeeds
		if cleanRulePath == cleanTargetPath {
			assert.True(t, result)
		}

		// Invariant 2: If match, target must have rule as path prefix (not just string prefix)
		if result && cleanRulePath != cleanTargetPath {
			assert.Greater(t, len(cleanTargetPath), len(cleanRulePath))
		}

		// Invariant 3: Directory boundary - string prefix without path boundary doesn't match
		// e.g., /home/user should not match /home/user2
		if !result && len(cleanTargetPath) > len(cleanRulePath) {
			// If it's a string prefix but not a match, the next char must not be "/"
			if len(cleanRulePath) > 0 && cleanTargetPath[:len(cleanRulePath)] == cleanRulePath {
				nextChar := cleanTargetPath[len(cleanRulePath)]
				assert.NotEqual(t, byte('/'), nextChar)
			}
		}
	})
}
