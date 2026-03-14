// Package config loads, merges, and validates execave TOML configuration files.
//
// [Load] traverses the "extends" chain, delegates rule parsing to [fsrules],
// [netrules], and [syscallrules], merges and deduplicates, injects synthetic
// rules, and validates the result. [RenderEffectiveTOML] renders the merged
// config back to TOML for inspection.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/netrules"
	"github.com/nonpop/execave/internal/pathutil"
	"github.com/nonpop/execave/internal/syscallrules"
)

// Config represents the merged, validated configuration from one or more TOML files.
type Config struct {
	FSRules      []fsrules.Rule      // Merged filesystem access rules.
	NetRules     []netrules.Rule     // Merged network access rules.
	SyscallRules []syscallrules.Rule // Merged syscall access rules.
	ManagedPaths []string            // Sandbox-managed paths (e.g., /proc, /dev, /tmp).
	ConfigPaths  []string            // Ordered list of config files loaded (root + extends).
}

type rawConfig struct {
	Extends []string `toml:"extends"`
	FS      []string `toml:"fs"`
	Net     []string `toml:"net"`
	Syscall []string `toml:"syscall"`
}

// buildConfig parses already-separated rule slices directly.
func buildConfig(raw rawConfig, configDir, configPath string, managedPaths []string) (*Config, error) { //nolint:cyclop // linear pipeline; complexity from error handling
	if !filepath.IsAbs(configPath) {
		panic(fmt.Sprintf("configPath must be absolute: %q", configPath))
	}

	fsAccess := make([]fsrules.Rule, 0, len(raw.FS))
	for i, r := range raw.FS {
		rule, err := fsrules.ParseRule(r, configDir, configPath)
		if err != nil {
			return nil, fmt.Errorf("parse fs rule %d: %w", i, err)
		}
		fsAccess = append(fsAccess, rule)
	}

	netAccess := make([]netrules.Rule, 0, len(raw.Net))
	for i, r := range raw.Net {
		rule, err := netrules.ParseAccessRule(r, configPath)
		if err != nil {
			return nil, fmt.Errorf("parse net rule %d: %w", i, err)
		}
		netAccess = append(netAccess, rule)
	}

	syscallAccess := make([]syscallrules.Rule, 0, len(raw.Syscall))
	for i, r := range raw.Syscall {
		rule, err := syscallrules.ParseRule(r, configPath)
		if err != nil {
			return nil, fmt.Errorf("parse syscall rule %d: %w", i, err)
		}
		syscallAccess = append(syscallAccess, rule)
	}

	if err := fsrules.ValidateRules(fsAccess, []string{configPath}, managedPaths); err != nil {
		return nil, fmt.Errorf("validate fs rules: %w", err)
	}

	if err := netrules.ValidateRules(netAccess); err != nil {
		return nil, fmt.Errorf("validate net rules: %w", err)
	}

	if err := syscallrules.ValidateRules(syscallAccess); err != nil {
		return nil, fmt.Errorf("validate syscall rules: %w", err)
	}

	return &Config{
		FSRules:      fsAccess,
		NetRules:     netAccess,
		SyscallRules: syscallAccess,
		ManagedPaths: managedPaths,
		ConfigPaths:  []string{configPath},
	}, nil
}

// Load reads, merges, and validates a configuration file and its extends chain.
// Injects synthetic read-only rules for config files, interpreterPath,
// tunnelBinary, and tunnelUDS (empty strings are skipped).
func Load(path string, managedPaths []string, interpreterPath, tunnelBinary, tunnelUDS string) (*Config, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve absolute path %s: %w", path, err)
	}
	absPath = filepath.Clean(absPath)

	cfgGraph, err := readConfigGraph(absPath)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", absPath, err)
	}

	configs := make([]*Config, 0, len(cfgGraph))
	configPaths := make([]string, 0, len(cfgGraph))
	for _, node := range cfgGraph {
		cfg, err := buildConfig(node.raw, node.dir, node.path, managedPaths)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", node.path, err)
		}
		configs = append(configs, cfg)
		configPaths = append(configPaths, node.path)
	}

	merged, err := mergeConfigs(configs, configPaths, managedPaths)
	if err != nil {
		return nil, fmt.Errorf("merge %s: %w", absPath, err)
	}

	merged.FSRules = appendForcedReadOnlyRules(merged.FSRules, merged.ConfigPaths, merged.ManagedPaths)
	merged.FSRules = appendSyntheticRORule(merged.FSRules, interpreterPath, merged.ManagedPaths)
	merged.FSRules = appendSyntheticRORule(merged.FSRules, tunnelBinary, merged.ManagedPaths)
	merged.FSRules = appendSyntheticRORule(merged.FSRules, tunnelUDS, merged.ManagedPaths)

	return merged, nil
}

type cfgNode struct {
	path string
	dir  string
	raw  rawConfig
}

func readConfigGraph(root string) ([]*cfgNode, error) { //nolint:cyclop // recursive graph walk; complexity from error handling
	visited := make(map[string]*cfgNode)
	inStack := make(map[string]struct{})
	var ordered []*cfgNode

	var visit func(string) error
	visit = func(path string) error {
		if _, ok := visited[path]; ok {
			return nil
		}
		if _, ok := inStack[path]; ok {
			return fmt.Errorf("cycle detected: %s", path)
		}

		inStack[path] = struct{}{}
		defer delete(inStack, path)

		data, err := os.ReadFile(path) //nolint:gosec // path is constructed from validated absolute paths
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("file not found: %s", path)
			}
			return fmt.Errorf("read %s: %w", path, err)
		}

		var raw rawConfig
		md, err := toml.Decode(string(data), &raw)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if undecoded := md.Undecoded(); len(undecoded) > 0 {
			return fmt.Errorf("parse %s: unknown config key %q", path, undecoded[0])
		}

		baseDir := filepath.Dir(path)
		for _, entry := range raw.Extends {
			if entry == "" {
				return fmt.Errorf("empty extends entry in %s", path)
			}
			resolved, err := pathutil.ExpandPath(entry, baseDir)
			if err != nil {
				return fmt.Errorf("invalid extends entry %q in %s: %w", entry, path, err)
			}
			if err := visit(resolved); err != nil {
				return err
			}
		}

		file := &cfgNode{
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

func mergeConfigs(configs []*Config, configPaths, managedPaths []string) (*Config, error) {
	merged := &Config{
		FSRules:      mergeFSRules(configs),
		NetRules:     mergeNetRules(configs),
		SyscallRules: mergeSyscallRules(configs),
		ManagedPaths: managedPaths,
		ConfigPaths:  configPaths,
	}

	if err := fsrules.ValidateRules(merged.FSRules, merged.ConfigPaths, merged.ManagedPaths); err != nil {
		return nil, fmt.Errorf("validate merged fs rules: %w", err)
	}
	if err := netrules.ValidateRules(merged.NetRules); err != nil {
		return nil, fmt.Errorf("validate merged net rules: %w", err)
	}
	if err := syscallrules.ValidateRules(merged.SyscallRules); err != nil {
		return nil, fmt.Errorf("validate merged syscall rules: %w", err)
	}

	return merged, nil
}

// appendForcedReadOnlyRules appends synthetic read-only rules for config file paths
// that would otherwise be writable (via a parent directory rule). These prevent
// sandboxed processes from modifying their own configuration.
func appendForcedReadOnlyRules(rules []fsrules.Rule, configPaths, managedPaths []string) []fsrules.Rule {
	resolver := fsrules.NewResolver(rules, managedPaths)
	seen := make(map[string]struct{})
	for _, path := range configPaths {
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		if resolver.PermissionFor(path) == fsrules.PermissionReadWrite {
			rules = append(rules, fsrules.Rule{
				Permission: fsrules.PermissionReadOnly,
				Path:       path,
				RawRule:    "ro:" + path,
				SourcePath: "",
			})
		}
	}
	return rules
}

// appendSyntheticRORule appends a synthetic read-only rule for the given path
// when no existing rule already covers it with read access. Empty paths are skipped.
func appendSyntheticRORule(rules []fsrules.Rule, path string, managedPaths []string) []fsrules.Rule {
	if path == "" {
		return rules
	}
	resolver := fsrules.NewResolver(rules, managedPaths)
	if resolver.PermissionFor(path) != fsrules.PermissionNone {
		return rules // already readable (RO or RW)
	}
	return append(rules, fsrules.Rule{
		Permission: fsrules.PermissionReadOnly,
		Path:       path,
		RawRule:    "ro:" + path,
		SourcePath: "",
	})
}

func mergeFSRules(configs []*Config) []fsrules.Rule {
	seen := make(map[string]struct{})
	result := make([]fsrules.Rule, 0)
	for _, cfg := range configs {
		for _, rule := range cfg.FSRules {
			key := rule.Canonical()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, rule)
		}
	}
	return result
}

func mergeNetRules(configs []*Config) []netrules.Rule {
	seen := make(map[string]struct{})
	result := make([]netrules.Rule, 0)
	for _, cfg := range configs {
		for _, rule := range cfg.NetRules {
			key := rule.Canonical()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, rule)
		}
	}
	return result
}

func mergeSyscallRules(configs []*Config) []syscallrules.Rule {
	seen := make(map[string]struct{})
	result := make([]syscallrules.Rule, 0)
	for _, cfg := range configs {
		for _, rule := range cfg.SyscallRules {
			key := rule.Canonical()
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, rule)
		}
	}
	return result
}
