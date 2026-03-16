// Package config loads, merges, and validates execave TOML configuration files.
//
// [Load] traverses the "extends" chain, delegates rule parsing to [fsrules],
// [netrules], [syscallrules], and [envrules], merges and deduplicates, injects
// synthetic rules, and validates the result. CLI rules are always merged after
// file-based rules; pass a zero-value [CLIRules] when no CLI flags are set.
// [RenderEffectiveTOML] renders the merged config back to TOML for inspection.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/nonpop/execave/internal/envrules"
	"github.com/nonpop/execave/internal/fsrules"
	"github.com/nonpop/execave/internal/netrules"
	"github.com/nonpop/execave/internal/pathutil"
	"github.com/nonpop/execave/internal/syscallrules"
)

// SourceCLI is the SourcePath sentinel for rules supplied via CLI flags.
const SourceCLI = "<cli>"

// SourceSynthetic is the SourcePath sentinel for rules injected by the runtime
// (e.g. forced read-only rules for config files, interpreter auto-mount).
const SourceSynthetic = "<synthetic>"

// CLIRules holds the raw rule strings from CLI flags passed to [Load].
// NoConfig skips loading the config file; all rules must come from CLI flags and Extends.
// NoConfig and ConfigExplicitlySet are mutually exclusive; Load returns an error if both are true.
type CLIRules struct {
	FS                  []string // Values from --fs flags.
	Net                 []string // Values from --net flags.
	Syscall             []string // Values from --syscall flags.
	Env                 []string // Values from --env flags.
	Extends             []string // Values from --extends flags.
	NoConfig            bool     // True when --no-config is set.
	ConfigExplicitlySet bool     // True when --config was explicitly provided (not defaulted).
}

// Config represents the merged, validated configuration from one or more TOML files.
type Config struct {
	FSRules      []fsrules.Rule      // Merged filesystem access rules.
	NetRules     []netrules.Rule     // Merged network access rules.
	SyscallRules []syscallrules.Rule // Merged syscall access rules.
	EnvRules     []envrules.Rule     // Merged environment variable filtering rules.
	ManagedPaths []string            // Sandbox-managed paths (e.g., /proc, /dev, /tmp).
	ConfigPaths  []string            // Ordered list of config files loaded (root + extends + sentinels).
}

type rawConfig struct {
	Extends []string `toml:"extends"`
	FS      []string `toml:"fs"`
	Net     []string `toml:"net"`
	Syscall []string `toml:"syscall"`
	Env     []string `toml:"env"`
}

// buildConfig parses already-separated rule slices directly.
// configPath must be an absolute path or a sentinel constant (SourceCLI).
func buildConfig(raw rawConfig, configDir, configPath string, managedPaths []string) (*Config, error) { //nolint:cyclop,funlen // linear pipeline; complexity from error handling
	if !filepath.IsAbs(configPath) && configPath != SourceCLI {
		panic(fmt.Sprintf("execave bug: config built with relative path: %q", configPath))
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

	envAccess := make([]envrules.Rule, 0, len(raw.Env))
	for i, r := range raw.Env {
		rule, err := envrules.ParseRule(r, configPath)
		if err != nil {
			return nil, fmt.Errorf("parse env rule %d: %w", i, err)
		}
		envAccess = append(envAccess, rule)
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

	if err := envrules.ValidateRules(envAccess); err != nil {
		return nil, fmt.Errorf("validate env rules: %w", err)
	}

	return &Config{
		FSRules:      fsAccess,
		NetRules:     netAccess,
		SyscallRules: syscallAccess,
		EnvRules:     envAccess,
		ManagedPaths: managedPaths,
		ConfigPaths:  []string{configPath},
	}, nil
}

// Load constructs a virtual CLI config node from cliRules (inline FS, Net,
// Syscall, and Env rules), then populates its extends list: configPath is
// prepended unless cliRules.NoConfig is true, followed by any cliRules.Extends
// entries. The full config tree rooted at that node is then read, merged, and
// validated using cwd as the base directory for relative paths in the CLI node.
// configPath may be relative; cliRules.Extends entries may be relative or use tilde.
// Injects synthetic read-only rules for config files, interpreterPath,
// tunnelBinary, and tunnelUDS (empty strings are skipped).
func Load(configPath string, cliRules CLIRules, managedPaths []string, interpreterPath, tunnelBinary, tunnelUDS string) (*Config, error) { //nolint:cyclop // linear pipeline; branches are error checks
	if cliRules.NoConfig && cliRules.ConfigExplicitlySet {
		panic("execave bug: CLIRules.NoConfig and CLIRules.ConfigExplicitlySet are mutually exclusive")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}

	// Build the CLI raw config: extends = config file (unless --no-config) + resolved --extends.
	cliRaw := rawConfig{FS: cliRules.FS, Net: cliRules.Net, Syscall: cliRules.Syscall, Env: cliRules.Env, Extends: nil}

	if !cliRules.NoConfig {
		absConfig, err := filepath.Abs(configPath)
		if err != nil {
			return nil, fmt.Errorf("resolve config path: %w", err)
		}
		cliRaw.Extends = append(cliRaw.Extends, filepath.Clean(absConfig))
	}

	for i, entry := range cliRules.Extends {
		if entry == "" {
			return nil, fmt.Errorf("empty --extends entry at position %d", i)
		}
		cliRaw.Extends = append(cliRaw.Extends, entry)
	}

	cfgNodes, err := readConfigGraph(cliRaw, cwd)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Use the config file path for merge-error context; fall back to SourceCLI.
	contextPath := SourceCLI
	if !cliRules.NoConfig && len(cliRaw.Extends) > 0 {
		contextPath = cliRaw.Extends[0]
	}

	return buildFromGraph(cfgNodes, managedPaths, interpreterPath, tunnelBinary, tunnelUDS, contextPath)
}

// buildFromGraph runs the buildConfig → mergeConfigs → synthetic-rules pipeline
// on an already-ordered list of config nodes.
func buildFromGraph(cfgGraph []*cfgNode, managedPaths []string, interpreterPath, tunnelBinary, tunnelUDS, contextLabel string) (*Config, error) {
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
		return nil, fmt.Errorf("merge %s: %w", contextLabel, err)
	}

	merged.FSRules = appendForcedReadOnlyRules(merged.FSRules, merged.ConfigPaths, merged.ManagedPaths)
	merged.FSRules = appendSyntheticRORule(merged.FSRules, interpreterPath, merged.ManagedPaths)
	merged.FSRules = appendSyntheticRORule(merged.FSRules, tunnelBinary, merged.ManagedPaths)
	merged.FSRules = appendSyntheticRORule(merged.FSRules, tunnelUDS, merged.ManagedPaths)
	merged.ConfigPaths = append(merged.ConfigPaths, SourceSynthetic)

	return merged, nil
}

type cfgNode struct {
	path string
	dir  string
	raw  rawConfig
}

// readRawConfig reads and decodes a TOML config file. path must be absolute.
func readRawConfig(path string) (rawConfig, string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is constructed from validated absolute paths
	if err != nil {
		if os.IsNotExist(err) {
			return rawConfig{}, "", fmt.Errorf("file not found: %s", path)
		}
		return rawConfig{}, "", fmt.Errorf("read %s: %w", path, err)
	}
	var raw rawConfig
	md, err := toml.Decode(string(data), &raw)
	if err != nil {
		return rawConfig{}, "", fmt.Errorf("parse %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return rawConfig{}, "", fmt.Errorf("parse %s: unknown config key %q", path, undecoded[0])
	}
	return raw, filepath.Dir(path), nil
}

// readConfigGraph traverses the extends chain rooted at root, using rootDir as
// the base directory for resolving extends paths in root. The root is stored as
// a SourceCLI node; file nodes use their absolute path. Returns nodes in
// depth-first post-order (extends before the node that references them).
func readConfigGraph(root rawConfig, rootDir string) ([]*cfgNode, error) {
	visited := make(map[string]*cfgNode)
	inStack := make(map[string]struct{})
	var ordered []*cfgNode

	var visit func(path string) error
	visit = func(path string) error {
		if _, ok := visited[path]; ok {
			return nil
		}
		if _, ok := inStack[path]; ok {
			return fmt.Errorf("cycle detected: %s", path)
		}

		inStack[path] = struct{}{}
		defer delete(inStack, path)

		var raw rawConfig
		var baseDir, nodePath string
		if path == "" {
			raw = root
			baseDir = rootDir
			nodePath = SourceCLI
		} else {
			var err error
			raw, baseDir, err = readRawConfig(path)
			if err != nil {
				return err
			}
			nodePath = path
		}

		src := nodePath // for error messages
		for _, entry := range raw.Extends {
			if entry == "" {
				return fmt.Errorf("empty extends entry in %s", src)
			}
			resolved, err := pathutil.ExpandPath(entry, baseDir)
			if err != nil {
				return fmt.Errorf("invalid extends entry %q in %s: %w", entry, src, err)
			}
			if err := visit(resolved); err != nil {
				return err
			}
		}

		node := &cfgNode{path: nodePath, dir: baseDir, raw: raw}
		visited[path] = node
		ordered = append(ordered, node)
		return nil
	}

	if err := visit(""); err != nil {
		return nil, err
	}
	return ordered, nil
}

func mergeConfigs(configs []*Config, configPaths, managedPaths []string) (*Config, error) {
	merged := &Config{
		FSRules:      mergeFSRules(configs),
		NetRules:     mergeNetRules(configs),
		SyscallRules: mergeSyscallRules(configs),
		EnvRules:     mergeEnvRules(configs),
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
	if err := envrules.ValidateRules(merged.EnvRules); err != nil {
		return nil, fmt.Errorf("validate merged env rules: %w", err)
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
		if strings.HasPrefix(path, "<") {
			// Skip sentinel constants like SourceCLI and SourceSynthetic.
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		if resolver.PermissionFor(path) == fsrules.PermissionReadWrite {
			rules = append(rules, fsrules.Rule{
				Permission: fsrules.PermissionReadOnly,
				Path:       path,
				RawRule:    "ro:" + path,
				SourcePath: SourceSynthetic,
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
		SourcePath: SourceSynthetic,
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

func mergeEnvRules(configs []*Config) []envrules.Rule {
	seen := make(map[string]struct{})
	result := make([]envrules.Rule, 0)
	for _, cfg := range configs {
		for _, rule := range cfg.EnvRules {
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
