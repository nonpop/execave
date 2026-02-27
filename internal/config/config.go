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
	"github.com/nonpop/execave/internal/seccomp"
)

// Config represents the parsed configuration file.
type Config struct {
	FSRules           []fsrules.AccessRule  // Access rules for filesystem paths.
	NetRules          []netrules.AccessRule // Access rules for network targets.
	FSLogRules        []fsrules.LogRule     // Log visibility rules for filesystem paths.
	NetLogRules       []netrules.LogRule    // Log visibility rules for network targets.
	SyscallAllowRules []string              // Syscall names allowed via syscall:allow rules.
	SyscallNologRules []string              // Syscall names hidden via syscall:nolog rules.
	ManagedPaths      []string              // Paths the sandbox manages (e.g., /proc, /dev, /tmp)
	InterpreterPath   string                // Auto-detected ELF interpreter (dynamic linker) path.
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

	return ParseRules(raw.Rules, configDir, configPath, managedPaths)
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

	parsed, err := parseRules(rawRules, configDir)
	if err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}

	if err := fsrules.ValidateAccessRules(parsed.fsAccess, configPath, managedPaths); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}

	if err := netrules.ValidateAccessRules(parsed.netAccess); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}

	if err := fsrules.ValidateLogRules(parsed.fsLog); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}

	if err := netrules.ValidateLogRules(parsed.netLog); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}

	if err := validateSyscallRules(parsed.syscallAllow, parsed.syscallNolog); err != nil {
		return nil, fmt.Errorf("validate rules: %w", err)
	}

	return &Config{
		FSRules:           parsed.fsAccess,
		NetRules:          parsed.netAccess,
		FSLogRules:        parsed.fsLog,
		NetLogRules:       parsed.netLog,
		SyscallAllowRules: parsed.syscallAllow,
		SyscallNologRules: parsed.syscallNolog,
		ManagedPaths:      managedPaths,
	}, nil
}

// validateSyscallRules checks that all syscall names are ruleable (blocked by
// seccomp and not defense-in-depth only) and that there are no duplicates within
// allow or nolog rule sets.
func validateSyscallRules(allowRules, nologRules []string) error {
	ruleableNames := make(map[string]bool)
	for _, name := range seccomp.RuleableSyscallNames() {
		ruleableNames[name] = true
	}

	// Validate allow rules
	seenAllow := make(map[string]bool)
	for _, name := range allowRules {
		if !ruleableNames[name] {
			return fmt.Errorf("syscall:allow:%s: %q is not a ruleable syscall name (defense-in-depth syscalls cannot be used in rules)", name, name)
		}
		if seenAllow[name] {
			return fmt.Errorf("duplicate syscall allow rule: %q", name)
		}
		seenAllow[name] = true
	}

	// Validate nolog rules
	seenNolog := make(map[string]bool)
	for _, name := range nologRules {
		if !ruleableNames[name] {
			return fmt.Errorf("syscall:nolog:%s: %q is not a ruleable syscall name (defense-in-depth syscalls cannot be used in rules)", name, name)
		}
		if seenNolog[name] {
			return fmt.Errorf("duplicate syscall nolog rule: %q", name)
		}
		seenNolog[name] = true
	}

	return nil
}

// actionNolog is the rule action string for nolog rules.
const actionNolog = "nolog"

// parsedRules holds all rule slices produced by parseRules.
type parsedRules struct {
	fsAccess     []fsrules.AccessRule
	netAccess    []netrules.AccessRule
	fsLog        []fsrules.LogRule
	netLog       []netrules.LogRule
	syscallAllow []string
	syscallNolog []string
}

// parseRules routes each raw rule string to the appropriate parser based on resource prefix.
// FS log rules (fs:log:, fs:nolog:) and net log rules (net:log:, net:nolog:) are routed
// to their respective log rule parsers; access rules go to the standard parsers.
// Syscall rules (syscall:allow:, syscall:nolog:) are accumulated as name strings.
func parseRules(rawRules []string, configDir string) (*parsedRules, error) {
	result := &parsedRules{
		fsAccess:     make([]fsrules.AccessRule, 0),
		netAccess:    make([]netrules.AccessRule, 0),
		fsLog:        make([]fsrules.LogRule, 0),
		netLog:       make([]netrules.LogRule, 0),
		syscallAllow: make([]string, 0),
		syscallNolog: make([]string, 0),
	}

	for i, rawRule := range rawRules {
		// Split on first colon to get resource prefix
		before, after, ok := strings.Cut(rawRule, ":")
		if !ok {
			return nil, fmt.Errorf("rule %d: malformed rule %q (expected format: resource:...)", i, rawRule)
		}

		switch before {
		case "fs":
			if err := parseFSRule(after, rawRule, configDir, &result.fsAccess, &result.fsLog); err != nil {
				return nil, fmt.Errorf("rule %d: %w", i, err)
			}
		case "net":
			if err := parseNetRule(after, rawRule, &result.netAccess, &result.netLog); err != nil {
				return nil, fmt.Errorf("rule %d: %w", i, err)
			}
		case "syscall":
			if err := parseSyscallRule(after, rawRule, &result.syscallAllow, &result.syscallNolog); err != nil {
				return nil, fmt.Errorf("rule %d: %w", i, err)
			}
		default:
			return nil, fmt.Errorf("rule %d: unknown resource type %q (must be 'fs' or 'net' or 'syscall')", i, before)
		}
	}

	return result, nil
}

// parseFSRule parses a single fs rule body and appends the result to the appropriate slice.
func parseFSRule(ruleBody, rawRule, configDir string, fsAccess *[]fsrules.AccessRule, fsLog *[]fsrules.LogRule) error {
	action, _, _ := strings.Cut(ruleBody, ":")
	if action == "log" || action == actionNolog {
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
	if action == "log" || action == actionNolog {
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

// parseSyscallRule parses a single syscall rule body and appends the name to the appropriate slice.
func parseSyscallRule(ruleBody, rawRule string, allow, nolog *[]string) error {
	action, name, ok := strings.Cut(ruleBody, ":")
	if !ok || name == "" {
		return fmt.Errorf("malformed syscall rule %q (expected format: syscall:action:name)", rawRule)
	}
	switch action {
	case "allow":
		*allow = append(*allow, name)
	case actionNolog:
		*nolog = append(*nolog, name)
	default:
		return fmt.Errorf("unknown syscall action %q (must be 'allow' or 'nolog')", action)
	}
	return nil
}
