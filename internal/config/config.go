// Package config handles parsing and validation of execave configuration files.
// It loads TOML configuration and routes resource-specific rules to their parsers.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	// SyscallAllowRuleSources maps syscall allow rule names to source config file paths.
	SyscallAllowRuleSources map[string][]string
	// SyscallNologRuleSources maps syscall nolog rule names to source config file paths.
	SyscallNologRuleSources map[string][]string
	ManagedPaths            []string // Paths the sandbox manages (e.g., /proc, /dev, /tmp)
	InterpreterPath         string   // Auto-detected ELF interpreter (dynamic linker) path.
	ConfigPaths             []string // Absolute ordered list of config files loaded (root + extends).
}

type rawConfig struct {
	Extends []string `toml:"extends"`
	FS      []string `toml:"fs"`
	Net     []string `toml:"net"`
	Syscall []string `toml:"syscall"`
}

// HasNetRules reports whether the configuration contains any network rules.
func (c *Config) HasNetRules() bool {
	return len(c.NetRules) > 0
}

// ParseTOML parses a TOML config from raw bytes.
// The configuration uses top-level array keys for rule sections:
//   - fs = ["ro:/usr", "rw:."] for filesystem rules
//   - net = ["http:api.example.com:443"] for network rules
//   - syscall = ["allow:ptrace"] for syscall rules
//
// Rules within each section are unprefixed strings.
// configDir is used to resolve relative and tilde-prefixed paths in fs rules;
// configPath must be an absolute path — same contract as ParseRules.
// ParseTOML panics if configPath is not absolute.
func ParseTOML(data []byte, configDir, configPath string, managedPaths []string) (*Config, error) {
	if !filepath.IsAbs(configPath) {
		panic(fmt.Sprintf("ParseTOML: configPath must be absolute, got %q", configPath))
	}

	var raw rawConfig
	if err := toml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	return parseRawConfig(raw, configDir, configPath, managedPaths)
}

func parseRawConfig(raw rawConfig, configDir, configPath string, managedPaths []string) (*Config, error) {
	// Reconstruct prefixed rule strings: fs rules first, then net, then syscall
	var rules []string
	for _, r := range raw.FS {
		rules = append(rules, "fs:"+r)
	}
	for _, r := range raw.Net {
		rules = append(rules, "net:"+r)
	}
	for _, r := range raw.Syscall {
		rules = append(rules, "syscall:"+r)
	}

	return ParseRules(rules, configDir, configPath, managedPaths)
}

// Load reads and parses a configuration file.
// The configuration uses top-level array keys (fs, net, syscall) for typed rule sections.
// It routes rules by resource type: fs rules go to fsrules, net rules go to netrules.
// managedPaths are path prefixes that fs rules cannot target (e.g., /proc, /dev).
func Load(path string, managedPaths []string) (*Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve absolute path for config %s: %w", path, err)
	}
	absPath = filepath.Clean(absPath)

	layeredFiles, err := collectLayeredFiles(absPath)
	if err != nil {
		return nil, err
	}

	configs := make([]*Config, 0, len(layeredFiles))
	configPaths := make([]string, 0, len(layeredFiles))
	for _, file := range layeredFiles {
		cfg, err := parseRawConfig(file.raw, file.dir, file.path, managedPaths)
		if err != nil {
			return nil, fmt.Errorf("config %s: %w", file.path, err)
		}
		setRuleSourcePaths(cfg, file.path)
		configs = append(configs, cfg)
		configPaths = append(configPaths, file.path)
	}

	merged, err := mergeConfigs(configs, configPaths, managedPaths)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", absPath, err)
	}

	return merged, nil
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
// already in memory.
func ParseRules(rawRules []string, configDir, configPath string, managedPaths []string) (*Config, error) {
	if !filepath.IsAbs(configPath) {
		panic(fmt.Sprintf("ParseRules: configPath must be absolute, got %q", configPath))
	}

	parsed, err := parseRules(rawRules, configDir)
	if err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}

	if err := fsrules.ValidateAccessRules(parsed.fsAccess, []string{configPath}, managedPaths); err != nil {
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
		FSRules:                 parsed.fsAccess,
		NetRules:                parsed.netAccess,
		FSLogRules:              parsed.fsLog,
		NetLogRules:             parsed.netLog,
		SyscallAllowRules:       parsed.syscallAllow,
		SyscallNologRules:       parsed.syscallNolog,
		ManagedPaths:            managedPaths,
		InterpreterPath:         "",
		SyscallAllowRuleSources: nil,
		SyscallNologRuleSources: nil,
		ConfigPaths:             nil,
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
	if action == actionLog || action == actionNolog {
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
	if action == actionLog || action == actionNolog {
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

type layeredFile struct {
	path string
	dir  string
	raw  rawConfig
}

func collectLayeredFiles(root string) ([]*layeredFile, error) {
	visited := make(map[string]*layeredFile)
	inStack := make(map[string]struct{})
	var ordered []*layeredFile

	var visit func(string) error
	visit = func(path string) error {
		if _, ok := visited[path]; ok {
			return nil
		}
		if _, ok := inStack[path]; ok {
			return fmt.Errorf("cycle detected expanding config extends: %s", path)
		}

		inStack[path] = struct{}{}
		defer delete(inStack, path)

		data, err := os.ReadFile(path) //nolint:gosec // path is constructed from validated absolute paths
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("config file not found: %s", path)
			}
			return fmt.Errorf("read config %s: %w", path, err)
		}

		var raw rawConfig
		if err := toml.Unmarshal(data, &raw); err != nil {
			return fmt.Errorf("parse config: %w", err)
		}

		baseDir := filepath.Dir(path)
		for _, entry := range raw.Extends {
			resolved, err := resolveExtendsPath(entry, baseDir)
			if err != nil {
				return fmt.Errorf("resolve extends %q: %w", entry, err)
			}
			if err := visit(resolved); err != nil {
				return err
			}
		}

		file := &layeredFile{
			path: path,
			dir:  baseDir,
			raw:  raw,
		}
		visited[path] = file
		ordered = append(ordered, file)
		return nil
	}

	if err := visit(root); err != nil {
		return nil, err
	}
	return ordered, nil
}

func resolveExtendsPath(entry, baseDir string) (string, error) {
	if entry == "" {
		return "", errors.New("empty extends entry")
	}

	path := entry
	switch {
	case path == "~":
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand tilde in path %q: %w", entry, err)
		}
		path = homeDir
	case strings.HasPrefix(path, "~/"):
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expand tilde in path %q: %w", entry, err)
		}
		path = homeDir + path[1:]
	case len(path) > 1 && path[0] == '~':
		return "", fmt.Errorf("~username paths not supported: %q", entry)
	}

	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	return filepath.Clean(path), nil
}

func setRuleSourcePaths(cfg *Config, sourcePath string) {
	for i := range cfg.FSRules {
		cfg.FSRules[i].SourcePath = sourcePath
	}
	for i := range cfg.NetRules {
		cfg.NetRules[i].SourcePath = sourcePath
	}
	for i := range cfg.FSLogRules {
		cfg.FSLogRules[i].SourcePath = sourcePath
	}
	for i := range cfg.NetLogRules {
		cfg.NetLogRules[i].SourcePath = sourcePath
	}
	if len(cfg.SyscallAllowRules) > 0 {
		cfg.SyscallAllowRuleSources = make(map[string][]string, len(cfg.SyscallAllowRules))
		for _, name := range cfg.SyscallAllowRules {
			cfg.SyscallAllowRuleSources[name] = []string{sourcePath}
		}
	}
	if len(cfg.SyscallNologRules) > 0 {
		cfg.SyscallNologRuleSources = make(map[string][]string, len(cfg.SyscallNologRules))
		for _, name := range cfg.SyscallNologRules {
			cfg.SyscallNologRuleSources[name] = []string{sourcePath}
		}
	}
}

func mergeConfigs(configs []*Config, configPaths, managedPaths []string) (*Config, error) {
	syscallAllowRules := mergeStringSlices(extractSyscallLists(configs, true))
	syscallNologRules := mergeStringSlices(extractSyscallLists(configs, false))

	merged := &Config{
		FSRules:                 mergeFSRules(configs),
		NetRules:                mergeNetRules(configs),
		FSLogRules:              mergeFSLogRules(configs),
		NetLogRules:             mergeNetLogRules(configs),
		SyscallAllowRules:       syscallAllowRules,
		SyscallNologRules:       syscallNologRules,
		SyscallAllowRuleSources: mergeSyscallRuleSources(configs, syscallAllowRules, true),
		SyscallNologRuleSources: mergeSyscallRuleSources(configs, syscallNologRules, false),
		ManagedPaths:            managedPaths,
		InterpreterPath:         "",
		ConfigPaths:             configPaths,
	}

	if err := fsrules.ValidateAccessRules(merged.FSRules, merged.ConfigPaths, merged.ManagedPaths); err != nil {
		return nil, fmt.Errorf("validate merged fs rules: %w", err)
	}
	if err := netrules.ValidateAccessRules(merged.NetRules); err != nil {
		return nil, fmt.Errorf("validate merged net rules: %w", err)
	}
	if err := fsrules.ValidateLogRules(merged.FSLogRules); err != nil {
		return nil, fmt.Errorf("validate merged fs log rules: %w", err)
	}
	if err := netrules.ValidateLogRules(merged.NetLogRules); err != nil {
		return nil, fmt.Errorf("validate merged net log rules: %w", err)
	}
	if err := validateSyscallRules(merged.SyscallAllowRules, merged.SyscallNologRules); err != nil {
		return nil, err
	}

	return merged, nil
}

func mergeFSRules(configs []*Config) []fsrules.AccessRule {
	seen := make(map[string]struct{})
	result := make([]fsrules.AccessRule, 0)
	for _, cfg := range configs {
		for _, rule := range cfg.FSRules {
			key := fmt.Sprintf("%d:%s", rule.Permission, rule.Path)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, rule)
		}
	}
	return result
}

func mergeNetRules(configs []*Config) []netrules.AccessRule {
	seen := make(map[string]struct{})
	result := make([]netrules.AccessRule, 0)
	for _, cfg := range configs {
		for _, rule := range cfg.NetRules {
			key := rule.Identity()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, rule)
		}
	}
	return result
}

func mergeFSLogRules(configs []*Config) []fsrules.LogRule {
	seen := make(map[string]struct{})
	result := make([]fsrules.LogRule, 0)
	for _, cfg := range configs {
		for _, rule := range cfg.FSLogRules {
			key := fmt.Sprintf("%t:%s", rule.Visible, rule.Path)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, rule)
		}
	}
	return result
}

func mergeNetLogRules(configs []*Config) []netrules.LogRule {
	seen := make(map[string]struct{})
	result := make([]netrules.LogRule, 0)
	for _, cfg := range configs {
		for _, rule := range cfg.NetLogRules {
			key := rule.Identity()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, rule)
		}
	}
	return result
}

func extractSyscallLists(configs []*Config, allow bool) [][]string {
	result := make([][]string, len(configs))
	for i, cfg := range configs {
		if allow {
			result[i] = cfg.SyscallAllowRules
		} else {
			result[i] = cfg.SyscallNologRules
		}
	}
	return result
}

func mergeStringSlices(lists [][]string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, list := range lists {
		for _, value := range list {
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}

func mergeSyscallRuleSources(configs []*Config, mergedRules []string, allow bool) map[string][]string {
	if len(mergedRules) == 0 {
		return nil
	}

	sources := make(map[string][]string, len(mergedRules))
	for _, name := range mergedRules {
		sources[name] = make([]string, 0, 1)
	}

	for _, cfg := range configs {
		var names []string
		var sourceMap map[string][]string
		if allow {
			names = cfg.SyscallAllowRules
			sourceMap = cfg.SyscallAllowRuleSources
		} else {
			names = cfg.SyscallNologRules
			sourceMap = cfg.SyscallNologRuleSources
		}
		for _, name := range names {
			existingSources, exists := sources[name]
			if !exists {
				continue
			}
			for _, sourcePath := range sourceMap[name] {
				if !slices.Contains(existingSources, sourcePath) {
					existingSources = append(existingSources, sourcePath)
				}
			}
			sources[name] = existingSources
		}
	}

	return sources
}
