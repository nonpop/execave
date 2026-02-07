// Package config handles parsing and validation of execave configuration files.
// It loads JSON configuration and routes resource-specific rules to their parsers.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
		Rules []string `json:"rules"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve absolute path for config %s: %w", path, err)
	}
	configDir := filepath.Dir(absPath)

	fsRules, netRules, err := parseRules(raw.Rules, configDir)
	if err != nil {
		return nil, fmt.Errorf("parse rules in %s: %w", path, err)
	}

	if err := fsrules.Validate(fsRules, absPath, managedPaths); err != nil {
		return nil, fmt.Errorf("validate config %s: %w", path, err)
	}

	if err := netrules.Validate(netRules); err != nil {
		return nil, fmt.Errorf("validate config %s: %w", path, err)
	}

	cfg := &Config{
		FSRules:      fsRules,
		NetRules:     netRules,
		ManagedPaths: managedPaths,
	}

	return cfg, nil
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
