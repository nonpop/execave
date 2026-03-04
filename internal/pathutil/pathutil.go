// Package pathutil provides path expansion and normalization utilities.
package pathutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ShortenPath returns a display form of absPath using strict priority:
//  1. Relative to configDir, if absPath is under configDir.
//  2. Tilde form (~/ or ~), if absPath is under homeDir.
//  3. The absolute path otherwise.
//
// absPath must be an absolute, clean path. An empty homeDir disables tilde
// shortening. An empty configDir skips step 1.
func ShortenPath(absPath, homeDir, configDir string) string {
	if !filepath.IsAbs(absPath) {
		panic("absPath must be absolute: " + absPath)
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

// ExpandPath expands tilde, resolves relative paths against baseDir, and cleans the result.
// A leading "~/" or bare "~" expands to os.UserHomeDir(). "~username" returns an error.
// If os.UserHomeDir() fails, an error is returned.
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
