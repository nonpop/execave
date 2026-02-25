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
	FSRules      []fsrules.AccessRule  // Access rules for filesystem paths.
	NetRules     []netrules.AccessRule // Access rules for network targets.
	FSLogRules   []fsrules.LogRule     // Log visibility rules for filesystem paths.
	NetLogRules  []netrules.LogRule    // Log visibility rules for network targets.
	ManagedPaths []string              // Paths the sandbox manages (e.g., /proc, /dev, /tmp)
}

// HasNetRules reports whether the configuration contains any network rules.
func (c *Config) HasNetRules() bool {
	return len(c.NetRules) > 0
}

// ParseTOML parses a TOML config from raw bytes.
// configDir is used to resolve relative and tilde-prefixed paths in fs rules;
// configPath must be an absolute path — same contract as ParseRules.
// ParseTOML panics if configPath is not absolute.
func ParseTOML(data []byte, configDir, configPath string, managedPaths []string) (*Config, error) {
	if !filepath.IsAbs(configPath) {
		panic(fmt.Sprintf("ParseTOML: configPath must be absolute, got %q", configPath))
	}

	var raw struct {
		Rules []string `toml:"rules"`
	}
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg, err := ParseRules(raw.Rules, configDir, configPath, managedPaths)
	if err != nil {
		return nil, err
	}

	return cfg, nil
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

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve absolute path for config %s: %w", path, err)
	}
	configDir := filepath.Dir(absPath)

	cfg, err := ParseTOML(data, configDir, absPath, managedPaths)
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
// writability, managed path rejection, net rule identity and port-pattern checks,
// and log rule validation (duplicate paths for fs, duplicate identity and mixed port
// patterns for net).
// Use Load when reading from a file; use ParseRules when the rule strings are
// already in memory (e.g., user-edited draft in the web UI).
func ParseRules(rawRules []string, configDir, configPath string, managedPaths []string) (*Config, error) {
	if !filepath.IsAbs(configPath) {
		panic(fmt.Sprintf("ParseRules: configPath must be absolute, got %q", configPath))
	}

	fsRules, netRules, fsLogRules, netLogRules, err := parseRules(rawRules, configDir)
	if err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}

	if err := fsrules.ValidateAccessRules(fsRules, configPath, managedPaths); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}

	if err := netrules.ValidateAccessRules(netRules); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}

	if err := fsrules.ValidateLogRules(fsLogRules); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}

	if err := netrules.ValidateLogRules(netLogRules); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}

	return &Config{
		FSRules:      fsRules,
		NetRules:     netRules,
		FSLogRules:   fsLogRules,
		NetLogRules:  netLogRules,
		ManagedPaths: managedPaths,
	}, nil
}

// parseRules routes each raw rule string to the appropriate parser based on resource prefix.
// FS log rules (fs:log:, fs:nolog:) and net log rules (net:log:, net:nolog:) are routed
// to their respective log rule parsers; access rules go to the standard parsers.
func parseRules(rawRules []string, configDir string) ([]fsrules.AccessRule, []netrules.AccessRule, []fsrules.LogRule, []netrules.LogRule, error) {
	fsAccessRules := make([]fsrules.AccessRule, 0)
	netAccessRules := make([]netrules.AccessRule, 0)
	fsLogRules := make([]fsrules.LogRule, 0)
	netLogRules := make([]netrules.LogRule, 0)

	for i, rawRule := range rawRules {
		// Split on first colon to get resource prefix
		before, after, ok := strings.Cut(rawRule, ":")
		if !ok {
			return nil, nil, nil, nil, fmt.Errorf("rule %d: malformed rule %q (expected format: resource:...)", i, rawRule)
		}

		switch before {
		case "fs":
			if err := parseFSRule(after, rawRule, configDir, &fsAccessRules, &fsLogRules); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("rule %d: %w", i, err)
			}
		case "net":
			if err := parseNetRule(after, rawRule, &netAccessRules, &netLogRules); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("rule %d: %w", i, err)
			}
		default:
			return nil, nil, nil, nil, fmt.Errorf("rule %d: unknown resource type %q (must be 'fs' or 'net')", i, before)
		}
	}

	return fsAccessRules, netAccessRules, fsLogRules, netLogRules, nil
}

// parseFSRule parses a single fs rule body and appends the result to the appropriate slice.
func parseFSRule(ruleBody, rawRule, configDir string, fsAccess *[]fsrules.AccessRule, fsLog *[]fsrules.LogRule) error {
	action, _, _ := strings.Cut(ruleBody, ":")
	if action == "log" || action == "nolog" {
		rule, err := fsrules.ParseLogRule(ruleBody, configDir)
		if err != nil {
			return err //nolint:wrapcheck // caller wraps with rule index context
		}
		rule.RawRule = rawRule
		*fsLog = append(*fsLog, rule)
	} else {
		rule, err := fsrules.ParseAccessRule(ruleBody, configDir)
		if err != nil {
			return err //nolint:wrapcheck // caller wraps with rule index context
		}
		rule.RawRule = rawRule
		*fsAccess = append(*fsAccess, rule)
	}
	return nil
}

// parseNetRule parses a single net rule body and appends the result to the appropriate slice.
func parseNetRule(ruleBody, rawRule string, netAccess *[]netrules.AccessRule, netLog *[]netrules.LogRule) error {
	action, _, _ := strings.Cut(ruleBody, ":")
	if action == "log" || action == "nolog" {
		rule, err := netrules.ParseLogRule(ruleBody)
		if err != nil {
			return err //nolint:wrapcheck // caller wraps with rule index context
		}
		rule.RawRule = rawRule
		*netLog = append(*netLog, rule)
	} else {
		rule, err := netrules.ParseAccessRule(ruleBody)
		if err != nil {
			return err //nolint:wrapcheck // caller wraps with rule index context
		}
		rule.RawRule = rawRule
		*netAccess = append(*netAccess, rule)
	}
	return nil
}
