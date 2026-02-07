// Package config handles parsing and validation of execave configuration files.
// It defines access rules that control filesystem permissions in the sandbox.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config represents the parsed configuration file.
type Config struct {
	Rules        []Rule
	ManagedPaths []string // Paths the sandbox manages (e.g., /proc, /dev, /tmp)
}

// Rule represents a parsed access rule.
type Rule struct {
	Resource   Resource
	Permission Permission
	Path       string
	RawRule    string // Original rule for error messages and logging
}

// Resource represents the type of resource a rule applies to.
type Resource int

const (
	// ResourceUnknown represents an uninitialized or invalid state.
	ResourceUnknown Resource = iota
	// ResourceFS represents filesystem access.
	ResourceFS
)

// Permission represents the access level. Higher values are stricter.
type Permission int

const (
	// PermissionUnknown represents an uninitialized or invalid state.
	PermissionUnknown Permission = iota
	// PermissionReadWrite grants read and write access.
	PermissionReadWrite
	// PermissionReadOnly grants read-only access.
	PermissionReadOnly
	// PermissionNone denies all access.
	PermissionNone
)

// Load reads and parses a configuration file.
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

	rules, err := parseRules(raw.Rules, configDir)
	if err != nil {
		return nil, fmt.Errorf("parse rules in %s: %w", path, err)
	}

	cfg := &Config{
		Rules:        rules,
		ManagedPaths: managedPaths,
	}

	if err := cfg.validate(absPath, managedPaths); err != nil {
		return nil, fmt.Errorf("validate config %s: %w", path, err)
	}

	return cfg, nil
}

func parseRules(rawRules []string, configDir string) ([]Rule, error) {
	rules := make([]Rule, 0, len(rawRules))

	for i, rawRule := range rawRules {
		rule, err := parseRule(rawRule, configDir)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

func parseRule(rawRule, configDir string) (Rule, error) {
	parts := strings.SplitN(rawRule, ":", 3)
	if len(parts) != 3 {
		return Rule{}, fmt.Errorf("malformed rule %q (expected format: resource:permission:path)", rawRule)
	}

	resourceStr := parts[0]
	permStr := parts[1]
	path := parts[2]

	var resource Resource
	switch resourceStr {
	case "fs":
		resource = ResourceFS
	default:
		return Rule{}, fmt.Errorf("unknown resource type %q (must be 'fs')", resourceStr)
	}

	var perm Permission
	switch permStr {
	case "rw":
		perm = PermissionReadWrite
	case "ro":
		perm = PermissionReadOnly
	case "none":
		perm = PermissionNone
	default:
		return Rule{}, fmt.Errorf("invalid permission type %q (must be 'ro', 'rw', or 'none')", permStr)
	}

	normalizedPath := normalizePath(path, configDir)

	return Rule{
		Resource:   resource,
		Permission: perm,
		Path:       normalizedPath,
		RawRule:    rawRule,
	}, nil
}

// normalizePath resolves relative paths against configDir and cleans the result.
func normalizePath(path, configDir string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(configDir, path)
	}
	return filepath.Clean(path)
}

func (c *Config) validate(configPath string, managedPaths []string) error {
	if err := c.validateNoDuplicates(); err != nil {
		return err
	}

	if err := c.validateConfigNotWritable(configPath); err != nil {
		return err
	}

	if err := c.validateNoManagedPaths(managedPaths); err != nil {
		return err
	}

	return nil
}

// validateNoDuplicates rejects configs with duplicate paths.
func (c *Config) validateNoDuplicates() error {
	seen := make(map[string]Rule)
	for _, rule := range c.Rules {
		if existing, ok := seen[rule.Path]; ok {
			return fmt.Errorf("duplicate path %q: rules %q and %q",
				rule.Path, existing.RawRule, rule.RawRule)
		}
		seen[rule.Path] = rule
	}
	return nil
}

// validateConfigNotWritable rejects configs that explicitly list the config file as writable.
func (c *Config) validateConfigNotWritable(configPath string) error {
	for _, rule := range c.Rules {
		if rule.Path == configPath && rule.Permission == PermissionReadWrite {
			return fmt.Errorf("config file must not be writable: rule %q", rule.RawRule)
		}
	}
	return nil
}

// validateNoManagedPaths rejects rules targeting paths the sandbox manages automatically.
func (c *Config) validateNoManagedPaths(managedPaths []string) error {
	for _, rule := range c.Rules {
		for _, managed := range managedPaths {
			if rule.Path == managed || strings.HasPrefix(rule.Path, managed+string(filepath.Separator)) {
				return fmt.Errorf("rule %q targets managed path %q", rule.RawRule, managed)
			}
		}
	}
	return nil
}
