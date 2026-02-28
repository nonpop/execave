// Package logfilter provides shared log filtering and display logic
// for access log consumers.
package logfilter

import (
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
		panic("ShortenPath: absPath must be absolute, got " + absPath)
	}
	if configDir != "" {
		if rel, err := filepath.Rel(configDir, absPath); err == nil && !strings.HasPrefix(rel, "..") {
			return rel
		}
	}

	if homeDir != "" {
		if rel, err := filepath.Rel(homeDir, absPath); err == nil && !strings.HasPrefix(rel, "..") {
			if rel == "." {
				return "~"
			}
			return "~/" + rel
		}
	}

	return absPath
}
