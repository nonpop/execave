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
)

// Config represents the parsed configuration file.
type Config struct {
	FSRules      []fsrules.Rule
	ManagedPaths []string // Paths the sandbox manages (e.g., /proc, /dev, /tmp)
}

// Load reads and parses a configuration file.
// It routes rules by resource prefix: "fs:" rules go to fsrules package.
// managedPaths are path prefixes that rules cannot target (e.g., /proc, /dev).
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

	fsRules, err := parseRules(raw.Rules, configDir)
	if err != nil {
		return nil, fmt.Errorf("parse rules in %s: %w", path, err)
	}

	if err := fsrules.Validate(fsRules, absPath, managedPaths); err != nil {
		return nil, fmt.Errorf("validate config %s: %w", path, err)
	}

	cfg := &Config{
		FSRules:      fsRules,
		ManagedPaths: managedPaths,
	}

	return cfg, nil
}

// parseRules routes each raw rule string to the appropriate parser based on resource prefix.
func parseRules(rawRules []string, configDir string) ([]fsrules.Rule, error) {
	rules := make([]fsrules.Rule, 0, len(rawRules))

	for i, rawRule := range rawRules {
		// Split on first colon to get resource prefix
		before, after, ok := strings.Cut(rawRule, ":")
		if !ok {
			return nil, fmt.Errorf("rule %d: malformed rule %q (expected format: resource:permission:path)", i, rawRule)
		}

		resourcePrefix := before
		ruleBody := after

		switch resourcePrefix {
		case "fs":
			rule, err := fsrules.Parse(ruleBody, configDir)
			if err != nil {
				return nil, fmt.Errorf("rule %d: %w", i, err)
			}
			rule.RawRule = rawRule
			rules = append(rules, rule)
		default:
			return nil, fmt.Errorf("rule %d: unknown resource type %q (must be 'fs')", i, resourcePrefix)
		}
	}

	return rules, nil
}
