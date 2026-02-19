// Package config handles parsing and validation of execave configuration files.
// It loads TOML configuration and routes resource-specific rules to their parsers.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/netrules"
)

// Config represents the parsed configuration file.
type Config struct {
	FSRules      []fsrules.Rule
	NetRules     []netrules.Rule
	ManagedPaths []string // Paths the sandbox manages (e.g., /proc, /dev, /tmp)
}

// HasNetRules reports whether the configuration contains any network rules.
func (c *Config) HasNetRules() bool {
	return len(c.NetRules) > 0
}

// Load reads and parses a configuration file.
// It routes rules by resource prefix: "fs:" rules go to fsrules, "net:" rules go to netrules.
// managedPaths are path prefixes that fs rules cannot target (e.g., /proc, /dev).
func Load(path string, managedPaths []string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is user-provided config file from CLI
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("config file not found: %s", path)
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var raw struct {
		Rules []string `toml:"rules"`
	}
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve absolute path for config %s: %w", path, err)
	}
	configDir := filepath.Dir(absPath)

	cfg, err := ParseRules(raw.Rules, configDir, absPath, managedPaths)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}

	return cfg, nil
}

// ParseRules parses and validates raw rule strings, returning a *Config.
//
// rawRules are strings in the format "resource:..."; configDir is used to resolve
// relative and tilde-prefixed paths in fs rules; configPath must be an absolute path
// — it is used only for the "config not writable" validation check and no I/O is
// performed, but a relative path would silently bypass that check; managedPaths lists
// path prefixes that rules may not target (e.g., sandbox.ManagedDirs).
//
// ParseRules panics if configPath is not absolute.
//
// ParseRules applies the same validation as Load: duplicate path detection, config
// writability, managed path rejection, and net rule identity and port-pattern checks.
// Use Load when reading from a file; use ParseRules when the rule strings are
// already in memory (e.g., user-edited draft in the web UI).
func ParseRules(rawRules []string, configDir, configPath string, managedPaths []string) (*Config, error) {
	if !filepath.IsAbs(configPath) {
		panic(fmt.Sprintf("ParseRules: configPath must be absolute, got %q", configPath))
	}

	fsRules, netRules, err := parseRules(rawRules, configDir)
	if err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}

	if err := fsrules.Validate(fsRules, configPath, managedPaths); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}

	if err := netrules.Validate(netRules); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}

	return &Config{
		FSRules:      fsRules,
		NetRules:     netRules,
		ManagedPaths: managedPaths,
	}, nil
}

// parseRules routes each raw rule string to the appropriate parser based on resource prefix.
func parseRules(rawRules []string, configDir string) ([]fsrules.Rule, []netrules.Rule, error) {
	fsRules := make([]fsrules.Rule, 0)
	netRules := make([]netrules.Rule, 0)

	for i, rawRule := range rawRules {
		// Split on first colon to get resource prefix
		before, after, ok := strings.Cut(rawRule, ":")
		if !ok {
			return nil, nil, fmt.Errorf("rule %d: malformed rule %q (expected format: resource:...)", i, rawRule)
		}

		resourcePrefix := before
		ruleBody := after

		switch resourcePrefix {
		case "fs":
			rule, err := fsrules.Parse(ruleBody, configDir)
			if err != nil {
				return nil, nil, fmt.Errorf("rule %d: %w", i, err)
			}
			rule.RawRule = rawRule
			fsRules = append(fsRules, rule)
		case "net":
			rule, err := netrules.Parse(ruleBody)
			if err != nil {
				return nil, nil, fmt.Errorf("rule %d: %w", i, err)
			}
			rule.RawRule = rawRule
			netRules = append(netRules, rule)
		default:
			return nil, nil, fmt.Errorf("rule %d: unknown resource type %q (must be 'fs' or 'net')", i, resourcePrefix)
		}
	}

	return fsRules, netRules, nil
}
