package config

import (
	"fmt"
	"strings"
)

type effectiveRule struct {
	canonical string
	source    string
}

// RenderEffectiveTOML renders the merged config as TOML with source-path comments.
// cfg must not be nil (panics otherwise).
func RenderEffectiveTOML(cfg *Config) string {
	if cfg == nil {
		panic("cfg must not be nil")
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
	rules := make([]effectiveRule, 0, len(cfg.FSRules))
	for _, rule := range cfg.FSRules {
		rules = append(rules, effectiveRule{
			canonical: rule.Canonical(),
			source:    rule.SourcePath,
		})
	}
	return rules
}

func renderNetRules(cfg *Config) []effectiveRule {
	rules := make([]effectiveRule, 0, len(cfg.NetRules))
	for _, rule := range cfg.NetRules {
		rules = append(rules, effectiveRule{
			canonical: rule.Canonical(),
			source:    rule.SourcePath,
		})
	}
	return rules
}

func renderSyscallRules(cfg *Config) []effectiveRule {
	rules := make([]effectiveRule, 0, len(cfg.SyscallRules))
	for _, rule := range cfg.SyscallRules {
		rules = append(rules, effectiveRule{
			canonical: rule.Canonical(),
			source:    rule.SourcePath,
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
		grouped[rule.source] = append(grouped[rule.source], rule.canonical)
	}

	for i, sourcePath := range orderedSourcePaths(grouped, configPaths) {
		if i > 0 {
			builder.WriteString("\n")
		}
		if sourcePath == "" {
			builder.WriteString("  # <synthetic>\n")
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
// then the empty (synthetic) source last.
func orderedSourcePaths(grouped map[string][]string, configPaths []string) []string {
	ordered := make([]string, 0, len(configPaths))
	for _, path := range configPaths {
		if len(grouped[path]) > 0 {
			ordered = append(ordered, path)
		}
	}
	if len(grouped[""]) > 0 {
		ordered = append(ordered, "")
	}
	return ordered
}
