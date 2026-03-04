// Package netrules implements network rule parsing, validation, and resolution.
//
// This package handles net-specific rule syntax (action:target:port), target
// classification (domain, IPv4, IPv6, CIDR), cross-rule validation (duplicate
// identity, mixed port patterns), and rule resolution (single-dimension target
// specificity, protocol compatibility, default-deny).
package netrules

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Protocol represents the action/protocol for a net rule.
type protocol int

const (
	// protocolUnknown is the zero value; it must not appear in validated rules.
	protocolUnknown protocol = iota
	// protocolNone denies all requests matching the rule's target and port.
	protocolNone
	// ProtocolHTTP allows HTTP and CONNECT (HTTPS) requests.
	ProtocolHTTP
)

const (
	// ipv4PrefixLen is the prefix length for an exact IPv4 address (32 bits).
	ipv4PrefixLen = 32
	// ipv6PrefixLen is the prefix length for an exact IPv6 address (128 bits).
	ipv6PrefixLen = 128
	// maxDNSLabelLen is the maximum length of a DNS label per RFC 1123.
	maxDNSLabelLen = 63
)

type targetKind int

const (
	targetDomain targetKind = iota
	targetIP
)

type target struct {
	kind      targetKind
	domain    string     // Lowercased domain pattern. Only meaningful when kind is targetDomain.
	wildcard  bool       // True if domain has "*." prefix. Only meaningful when kind is targetDomain.
	ipNet     *net.IPNet // Parsed IP network (/32 or /128 for exact). Only meaningful when kind is targetIP.
	prefixLen int        // CIDR prefix length. Only meaningful when kind is targetIP.
}

type port struct {
	isWildcard bool   // True when port is "*" (matches any port).
	number     uint16 // Port number. Only meaningful when isWildcard is false.
}

// Rule represents a parsed network access rule.
type Rule struct {
	protocol        protocol
	target          target
	port            port
	RawRule         string // Original rule for error messages and logging
	canonicalTarget string // Canonical target pattern for validation identity.
	canonicalPort   string // Raw port string ("443" or "*") for validation identity.
	SourcePath      string // Config file path that produced this rule.
}

// Canonical returns the canonical version of the rule, suitable for deduplication, comparison, and rendering.
func (r Rule) Canonical() string {
	var proto string
	switch r.protocol {
	case ProtocolHTTP:
		proto = "http"
	case protocolNone:
		proto = "none"
	default:
		panic(fmt.Sprintf("unknown protocol %d", r.protocol))
	}
	return fmt.Sprintf("%s:%s:%s", proto, r.canonicalTarget, r.canonicalPort)
}

// ParseAccessRule parses an access rule body in the format "action:target:port".
func ParseAccessRule(rawRule, configPath string) (Rule, error) {
	action, rest, ok := strings.Cut(rawRule, ":")
	if !ok {
		return Rule{}, fmt.Errorf("malformed rule %q: expected format: action:target:port", rawRule)
	}
	targetStr, portStr, err := splitTargetPort(rest)
	if err != nil {
		return Rule{}, fmt.Errorf("malformed rule %q: expected format: action:target:port", rawRule)
	}

	protocol, err := parseProtocol(action)
	if err != nil {
		return Rule{}, fmt.Errorf("malformed rule %q: %w", rawRule, err)
	}

	parsedPort, rawPort, err := parsePort(portStr)
	if err != nil {
		return Rule{}, fmt.Errorf("malformed rule %q: %w", rawRule, err)
	}

	parsedTarget, rawTarget, err := parseTarget(targetStr)
	if err != nil {
		return Rule{}, fmt.Errorf("malformed rule %q: %w", rawRule, err)
	}

	return Rule{
		protocol:        protocol,
		target:          parsedTarget,
		port:            parsedPort,
		RawRule:         rawRule,
		canonicalTarget: rawTarget,
		canonicalPort:   rawPort,
		SourcePath:      configPath,
	}, nil
}

// ValidateRules performs cross-rule validation: checks for duplicate (target, port)
// identity and mixed port patterns (wildcard + specific on the same target).
func ValidateRules(rules []Rule) error {
	if err := validateNoDuplicateAccessIdentity(rules); err != nil {
		return err
	}
	if err := validateNoMixedPortAccessPatterns(rules); err != nil {
		return err
	}
	return nil
}

func parseProtocol(action string) (protocol, error) {
	switch action {
	case "http":
		return ProtocolHTTP, nil
	case "none":
		return protocolNone, nil
	default:
		return protocolUnknown, fmt.Errorf("invalid action %q: must be 'http' or 'none'", action)
	}
}

// splitTargetPort splits "target:port" by finding the last colon.
// This works because IPv6 addresses are always bracketed and CIDR suffixes
// follow the closing bracket, so the last colon is always the port separator.
func splitTargetPort(s string) (string, string, error) {
	lastColon := strings.LastIndex(s, ":")
	if lastColon < 0 {
		return "", "", fmt.Errorf("no port separator found in %q", s)
	}
	return s[:lastColon], s[lastColon+1:], nil
}

func parsePort(portStr string) (port, string, error) {
	if portStr == "*" {
		return port{isWildcard: true, number: 0}, "*", nil
	}

	n, err := strconv.ParseUint(portStr, 10, 32)
	if err != nil || n < 1 || n > 65535 {
		return port{}, "", fmt.Errorf("invalid port %q: must be 1-65535 or '*'", portStr)
	}

	return port{number: uint16(n), isWildcard: false}, portStr, nil
}

// parseTarget parses the target string into a target. Returns the parsed target
// and its canonical string form (for validation identity).
//
// Parsing order:
//  1. Bracketed IPv6 (starts with '[')
//  2. CIDR (net.ParseCIDR)
//  3. Exact IP (net.ParseIP)
//  4. Domain pattern
func parseTarget(targetStr string) (target, string, error) {
	// Step 1: Bracketed IPv6 or IPv6 CIDR
	if strings.HasPrefix(targetStr, "[") {
		return parseBracketedIPv6(targetStr)
	}

	// Reject unbracketed IPv6 (contains a colon but didn't start with '[')
	if strings.Contains(targetStr, ":") {
		return target{}, "", fmt.Errorf("invalid target %q: IPv6 addresses must be bracketed", targetStr)
	}

	// Step 2: IPv4 CIDR
	_, ipNet, err := net.ParseCIDR(targetStr)
	if err == nil {
		prefixLen, _ := ipNet.Mask.Size()
		canonical := ipNet.String()
		return target{
			kind:      targetIP,
			domain:    "",
			wildcard:  false,
			ipNet:     ipNet,
			prefixLen: prefixLen,
		}, canonical, nil
	}

	// Step 3: Exact IPv4
	ip := net.ParseIP(targetStr)
	if ip != nil {
		return makeExactIPTarget(ip)
	}

	// Step 4: Domain
	return parseDomainTarget(targetStr)
}

func parseBracketedIPv6(targetStr string) (target, string, error) {
	closeBracket := strings.Index(targetStr, "]")
	if closeBracket < 0 {
		return target{}, "", fmt.Errorf("invalid target %q: missing closing bracket", targetStr)
	}

	ipStr := targetStr[1:closeBracket]
	suffix := targetStr[closeBracket+1:]

	// Brackets commit to IPv6 parsing. Reject IPv4 addresses (which lack colons)
	// to prevent e.g. [127.0.0.1] from being silently accepted as valid.
	if !strings.Contains(ipStr, ":") {
		if suffix == "" {
			return target{}, "", fmt.Errorf("invalid target %q: invalid IPv6 address", targetStr)
		}
		return target{}, "", fmt.Errorf("invalid target %q: invalid IPv6 CIDR: not an IPv6 address", targetStr)
	}

	if suffix == "" {
		// Exact IPv6: [::1]
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return target{}, "", fmt.Errorf("invalid target %q: invalid IPv6 address", targetStr)
		}
		return makeExactIPTarget(ip)
	}

	if strings.HasPrefix(suffix, "/") {
		// IPv6 CIDR: [2001:db8::]/32
		cidrStr := ipStr + suffix
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return target{}, "", fmt.Errorf("invalid target %q: invalid IPv6 CIDR: %w", targetStr, err)
		}
		prefixLen, _ := ipNet.Mask.Size()
		canonical := fmt.Sprintf("[%s]/%d", ipNet.IP.String(), prefixLen)
		return target{
			kind:      targetIP,
			domain:    "",
			wildcard:  false,
			ipNet:     ipNet,
			prefixLen: prefixLen,
		}, canonical, nil
	}

	return target{}, "", fmt.Errorf("invalid target %q: unexpected text after closing bracket", targetStr)
}

func makeExactIPTarget(addr net.IP) (target, string, error) {
	// Normalize IPv4-mapped IPv6 to IPv4
	if v4 := addr.To4(); v4 != nil {
		mask := net.CIDRMask(ipv4PrefixLen, ipv4PrefixLen)
		ipNet := &net.IPNet{IP: v4, Mask: mask}
		return target{
			kind:      targetIP,
			domain:    "",
			wildcard:  false,
			ipNet:     ipNet,
			prefixLen: ipv4PrefixLen,
		}, ipNet.String(), nil
	}

	mask := net.CIDRMask(ipv6PrefixLen, ipv6PrefixLen)
	ipNet := &net.IPNet{IP: addr, Mask: mask}
	canonical := fmt.Sprintf("[%s]/%d", addr.String(), ipv6PrefixLen)
	return target{
		kind:      targetIP,
		domain:    "",
		wildcard:  false,
		ipNet:     ipNet,
		prefixLen: ipv6PrefixLen,
	}, canonical, nil
}

func parseDomainTarget(targetStr string) (target, string, error) {
	lower := strings.ToLower(targetStr)

	wildcard := false
	domainToValidate := lower

	if strings.HasPrefix(lower, "*.") {
		wildcard = true
		domainToValidate = lower[2:]
		if len(domainToValidate) == 0 {
			return target{}, "", fmt.Errorf("invalid domain pattern %q: empty domain after wildcard", targetStr)
		}
	} else if strings.Contains(lower, "*") {
		return target{}, "", fmt.Errorf("invalid domain pattern %q: wildcard must be single '*' in leftmost position only", targetStr)
	}

	if err := validateDomainLabels(domainToValidate); err != nil {
		return target{}, "", fmt.Errorf("invalid domain pattern %q: %w", targetStr, err)
	}

	return target{
		kind:      targetDomain,
		domain:    lower,
		wildcard:  wildcard,
		ipNet:     nil,
		prefixLen: 0,
	}, lower, nil
}

// validateDomainLabels validates domain labels per RFC 1123.
// The last label must contain at least one alphabetic character (rejects all-numeric TLDs).
func validateDomainLabels(domain string) error {
	labels := strings.Split(domain, ".")
	for i, label := range labels {
		if err := validateLabel(label); err != nil {
			return fmt.Errorf("invalid label %q: %w", label, err)
		}
		if i == len(labels)-1 {
			if err := validateTLD(label); err != nil {
				return fmt.Errorf("invalid label %q: %w", label, err)
			}
		}
	}
	return nil
}

// validateLabel validates a single DNS label per RFC 1123.
func validateLabel(label string) error {
	if len(label) == 0 {
		return fmt.Errorf("empty")
	}
	if len(label) > maxDNSLabelLen {
		return fmt.Errorf("exceeds %d characters", maxDNSLabelLen)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("must not start or end with hyphen")
	}
	for _, c := range label {
		if !isLabelChar(c) {
			return fmt.Errorf("contains invalid character %q", c)
		}
	}
	return nil
}

// validateTLD ensures the TLD contains at least one alphabetic character.
func validateTLD(label string) error {
	for _, c := range label {
		if c >= 'a' && c <= 'z' {
			return nil
		}
	}
	return fmt.Errorf("last label must contain at least one alphabetic character")
}

func isLabelChar(c rune) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
}

// validateNoDuplicateAccessIdentity rejects configs where two access rules have the same
// (target-pattern, port-pattern) pair.
func validateNoDuplicateAccessIdentity(rules []Rule) error {
	type identity struct {
		target string
		port   string
	}
	seen := make(map[identity]Rule)
	for _, rule := range rules {
		ruleID := identity{target: rule.canonicalTarget, port: rule.canonicalPort}
		if existing, ok := seen[ruleID]; ok {
			if existing.SourcePath != "" && existing.SourcePath == rule.SourcePath {
				return fmt.Errorf("duplicate net rule identity (%s, %s) in %s: %q and %q",
					rule.canonicalTarget, rule.canonicalPort, existing.SourcePath, existing.RawRule, rule.RawRule)
			}
			return fmt.Errorf("duplicate net rule identity (%s, %s): %q (%q) and %q (%q)",
				rule.canonicalTarget, rule.canonicalPort,
				existing.RawRule, existing.SourcePath,
				rule.RawRule, rule.SourcePath)
		}
		seen[ruleID] = rule
	}
	return nil
}

// validateNoMixedPortAccessPatterns rejects configs where a target has both wildcard
// and specific port access rules.
func validateNoMixedPortAccessPatterns(rules []Rule) error {
	type portInfo struct {
		hasWildcard bool
		hasSpecific bool
		firstRule   Rule
	}
	byTarget := make(map[string]*portInfo)
	for _, rule := range rules {
		info, ok := byTarget[rule.canonicalTarget]
		if !ok {
			info = &portInfo{
				hasWildcard: false,
				hasSpecific: false,
				firstRule:   rule,
			}
			byTarget[rule.canonicalTarget] = info
		}
		if rule.port.isWildcard {
			info.hasWildcard = true
		} else {
			info.hasSpecific = true
		}
		if info.hasWildcard && info.hasSpecific {
			return fmt.Errorf("mixed port patterns for target %q: rules %q and %q have both wildcard and specific ports",
				rule.canonicalTarget, info.firstRule.RawRule, rule.RawRule)
		}
	}
	return nil
}
