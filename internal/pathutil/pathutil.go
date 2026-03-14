// Package pathutil provides path expansion and display-shortening utilities
// used at config-load time and in access log formatting.
package pathutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IsUnder reports whether path is equal to dir or is a child of dir.
// Both must be clean paths (caller responsibility).
func IsUnder(path, dir string) bool {
	return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
}

// ShortenPath returns a compact display form of absPath, preferring
// config-relative, then tilde-relative, then absolute.
//
// absPath must be absolute (panics otherwise). Empty homeDir or configDir
// disables the corresponding shortening.
func ShortenPath(absPath, homeDir, configDir string) string {
	if !filepath.IsAbs(absPath) {
		panic("execave bug: ShortenPath received relative path: " + absPath)
	}
	if rel, err := filepath.Rel(configDir, absPath); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}

	if rel, err := filepath.Rel(homeDir, absPath); err == nil && !strings.HasPrefix(rel, "..") {
		if rel == "." {
			return "~"
		}
		return "~/" + rel
	}

	return absPath
}

// ExpandPath normalizes a user-provided path to a clean absolute path.
// Expands "~/" and "~" via [os.UserHomeDir]; rejects "~username".
// Relative paths resolve against baseDir. Returns an error if tilde
// expansion fails.
func ExpandPath(path, baseDir string) (string, error) {
	switch {
	case strings.HasPrefix(path, "~/"):
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand tilde in path %q: %w", path, err)
		}
		path = homeDir + path[1:] // path[1:] = "/" + rest
	case path == "~":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand tilde in path %q: %w", path, err)
		}
		path = homeDir
	case len(path) > 1 && path[0] == '~':
		return "", fmt.Errorf("~username paths not supported: %q", path)
	}

	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	return filepath.Clean(path), nil
}
