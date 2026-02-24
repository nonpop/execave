package netrules

import (
	"fmt"
	"net"
	"strings"
)

// LogRule represents a parsed network log visibility rule.
type LogRule struct {
	// Visible is true for log rules (show entry) and false for nolog rules (hide entry).
	Visible bool
	target  target
	port    port
	// RawRule is the original rule body, for error messages.
	// Initialized to ruleBody by ParseLogRule; the config layer overwrites it
	// with the full rule string including the resource prefix.
	RawRule   string
	rawTarget string // canonical target pattern for validation identity
	rawPort   string // raw port string for validation identity
}

// ParseLogRule parses a log rule body in the format "visibility:target:port".
// The resource prefix ("net:") must be stripped by the caller before passing.
func ParseLogRule(ruleBody string) (LogRule, error) {
	vis, rest, ok := strings.Cut(ruleBody, ":")
	if !ok {
		return LogRule{}, fmt.Errorf("malformed rule %q (expected format: visibility:target:port)", ruleBody)
	}

	var visible bool
	switch vis {
	case "log":
		visible = true
	case "nolog":
		visible = false
	default:
		return LogRule{}, fmt.Errorf("invalid visibility type %q (must be 'log' or 'nolog')", vis)
	}

	targetStr, portStr, err := splitTargetPort(rest)
	if err != nil {
		return LogRule{}, fmt.Errorf("malformed rule %q (expected format: visibility:target:port)", ruleBody)
	}

	parsedPort, rawPort, err := parsePort(portStr)
	if err != nil {
		return LogRule{}, err
	}

	parsedTarget, rawTarget, err := parseTarget(targetStr)
	if err != nil {
		return LogRule{}, err
	}

	return LogRule{
		Visible:   visible,
		target:    parsedTarget,
		port:      parsedPort,
		RawRule:   ruleBody,
		rawTarget: rawTarget,
		rawPort:   rawPort,
	}, nil
}

// ValidateLogRules performs cross-rule validation: checks for duplicate (target, port)
// identity and mixed port patterns (wildcard + specific on the same target).
func ValidateLogRules(rules []LogRule) error {
	if err := validateNoLogDuplicateIdentity(rules); err != nil {
		return err
	}
	if err := validateNoLogMixedPortPatterns(rules); err != nil {
		return err
	}
	return nil
}

// validateNoLogDuplicateIdentity rejects log rule sets where two rules have the
// same (target-pattern, port-pattern) pair.
func validateNoLogDuplicateIdentity(rules []LogRule) error {
	type identity struct {
		target string
		port   string
	}
	seen := make(map[identity]LogRule)
	for _, rule := range rules {
		id := identity{target: rule.rawTarget, port: rule.rawPort}
		if existing, ok := seen[id]; ok {
			return fmt.Errorf("duplicate net log rule identity (%s, %s): rules %q and %q",
				rule.rawTarget, rule.rawPort, existing.RawRule, rule.RawRule)
		}
		seen[id] = rule
	}
	return nil
}

// validateNoLogMixedPortPatterns rejects log rule sets where a target has both
// wildcard and specific port rules.
func validateNoLogMixedPortPatterns(rules []LogRule) error {
	type portInfo struct {
		hasWildcard bool
		hasSpecific bool
		firstRule   LogRule
	}
	byTarget := make(map[string]*portInfo)
	for _, rule := range rules {
		info, ok := byTarget[rule.rawTarget]
		if !ok {
			info = &portInfo{firstRule: rule}
			byTarget[rule.rawTarget] = info
		}
		if rule.port.isWildcard {
			info.hasWildcard = true
		} else {
			info.hasSpecific = true
		}
		if info.hasWildcard && info.hasSpecific {
			return fmt.Errorf("mixed port patterns for target %q: rules %q and %q have both wildcard and specific ports",
				rule.rawTarget, info.firstRule.RawRule, rule.RawRule)
		}
	}
	return nil
}

// LogResolver determines whether an entry for a given host and port should be displayed.
// It uses the same single-dimension target specificity as the access Resolver.
type LogResolver struct {
	rules []LogRule
}

// NewLogResolver creates a new LogResolver from the given log rules.
func NewLogResolver(rules []LogRule) *LogResolver {
	return &LogResolver{rules: rules}
}

// Visible returns true if entries for the given host and port should be displayed.
// Resolution is protocol-agnostic: it matches on target and port only.
// If no rule matches, the default is visible (true).
func (r *LogResolver) Visible(host string, port uint16) bool {
	lowerHost := strings.ToLower(host)
	parsedIP := net.ParseIP(lowerHost)

	var bestRule *LogRule
	bestSpecificity := -1

	for i := range r.rules {
		rule := &r.rules[i]

		if !portMatches(rule.port, port) {
			continue
		}

		// Reuse targetSpecificity by wrapping the log rule target in a Rule struct.
		tmpRule := &AccessRule{target: rule.target}
		specificity := targetSpecificity(tmpRule, lowerHost, parsedIP)
		if specificity < 0 {
			continue
		}

		if specificity > bestSpecificity {
			bestSpecificity = specificity
			bestRule = rule
		}
	}

	if bestRule == nil {
		return true // default: visible
	}
	return bestRule.Visible
}
