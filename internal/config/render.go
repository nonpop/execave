package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/nonpop/execave/internal/fsrules"
)

const actionLog = "log"

type effectiveRule struct {
	body   string
	source string
}

// RenderEffectiveTOML renders the effective config as TOML with source-path comments.
// RenderEffectiveTOML panics if cfg is nil.
func RenderEffectiveTOML(cfg *Config) string {
	if cfg == nil {
		panic("RenderEffectiveTOML: cfg must not be nil")
	}

	fsRules := renderFSRules(cfg)
	netRules := renderNetRules(cfg)
	syscallRules := renderSyscallRules(cfg)

	var builder strings.Builder
	appendSection(&builder, "fs", fsRules, cfg.ConfigPaths)
	appendSection(&builder, "net", netRules, cfg.ConfigPaths)
	appendSection(&builder, "syscall", syscallRules, cfg.ConfigPaths)
	return builder.String()
}

func renderFSRules(cfg *Config) []effectiveRule {
	rules := make([]effectiveRule, 0, len(cfg.FSRules)+len(cfg.FSLogRules))
	for _, rule := range cfg.FSRules {
		rules = append(rules, effectiveRule{
			body:   fmt.Sprintf("%s:%s", permissionLabel(rule.Permission), rule.Path),
			source: rule.SourcePath,
		})
	}
	for _, rule := range cfg.FSLogRules {
		rules = append(rules, effectiveRule{
			body:   fmt.Sprintf("%s:%s", visibilityLabel(rule.Visible), rule.Path),
			source: rule.SourcePath,
		})
	}
	return rules
}

func renderNetRules(cfg *Config) []effectiveRule {
	rules := make([]effectiveRule, 0, len(cfg.NetRules)+len(cfg.NetLogRules))
	for _, rule := range cfg.NetRules {
		rules = append(rules, effectiveRule{
			body:   stripPrefix(rule.RawRule, "net:"),
			source: rule.SourcePath,
		})
	}
	for _, rule := range cfg.NetLogRules {
		rules = append(rules, effectiveRule{
			body:   stripPrefix(rule.RawRule, "net:"),
			source: rule.SourcePath,
		})
	}
	return rules
}

func renderSyscallRules(cfg *Config) []effectiveRule {
	rules := make([]effectiveRule, 0, len(cfg.SyscallAllowRules)+len(cfg.SyscallNologRules))
	for _, name := range cfg.SyscallAllowRules {
		rules = append(rules, effectiveRule{
			body:   "allow:" + name,
			source: firstSourcePath(cfg.SyscallAllowRuleSources, name),
		})
	}
	for _, name := range cfg.SyscallNologRules {
		rules = append(rules, effectiveRule{
			body:   "nolog:" + name,
			source: firstSourcePath(cfg.SyscallNologRuleSources, name),
		})
	}
	return rules
}

func appendSection(builder *strings.Builder, section string, rules []effectiveRule, configPaths []string) {
	if len(rules) == 0 {
		return
	}
	if builder.Len() > 0 {
		builder.WriteString("\n")
	}

	fmt.Fprintf(builder, "%s = [\n", section)
	grouped := make(map[string][]string, len(configPaths))
	for _, rule := range rules {
		grouped[rule.source] = append(grouped[rule.source], rule.body)
	}

	for i, sourcePath := range orderedSourcePaths(grouped, configPaths, rules) {
		if i > 0 {
			builder.WriteString("\n")
		}
		if sourcePath == "" {
			builder.WriteString("  # <unknown>\n")
		} else {
			fmt.Fprintf(builder, "  # %s\n", sourcePath)
		}
		for _, body := range grouped[sourcePath] {
			fmt.Fprintf(builder, "  %q,\n", body)
		}
	}
	builder.WriteString("]\n")
}

// orderedSourcePaths returns source paths in a stable order: config-file order first,
// then any remaining non-empty sources, then the empty (unknown) source last.
func orderedSourcePaths(grouped map[string][]string, configPaths []string, rules []effectiveRule) []string {
	ordered := make([]string, 0, len(configPaths))
	for _, path := range configPaths {
		if len(grouped[path]) > 0 {
			ordered = append(ordered, path)
		}
	}
	for _, rule := range rules {
		if rule.source != "" && !slices.Contains(ordered, rule.source) && len(grouped[rule.source]) > 0 {
			ordered = append(ordered, rule.source)
		}
	}
	if len(grouped[""]) > 0 {
		ordered = append(ordered, "")
	}
	return ordered
}

// stripPrefix removes expectedPrefix from value, panicking if the prefix is absent.
// The prefix is an invariant established during config parsing; absence indicates a bug.
func stripPrefix(value, expectedPrefix string) string {
	if !strings.HasPrefix(value, expectedPrefix) {
		panic(fmt.Sprintf("render effective config: rule %q missing expected prefix %q", value, expectedPrefix))
	}
	return strings.TrimPrefix(value, expectedPrefix)
}

func firstSourcePath(sourceMap map[string][]string, key string) string {
	if sourceMap == nil {
		return ""
	}
	sources := sourceMap[key]
	if len(sources) == 0 {
		return ""
	}
	return sources[0]
}

func permissionLabel(permission fsrules.Permission) string {
	switch permission {
	case fsrules.PermissionReadOnly:
		return "ro"
	case fsrules.PermissionReadWrite:
		return "rw"
	case fsrules.PermissionNone:
		return "none"
	case fsrules.PermissionUnknown:
		panic("render effective config: filesystem rule has unknown permission")
	}
	panic(fmt.Sprintf("render effective config: unexpected filesystem permission value %d", permission))
}

func visibilityLabel(visible bool) string {
	if visible {
		return actionLog
	}
	return actionNolog
}
