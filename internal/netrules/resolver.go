package netrules

import (
	"net"
	"strings"
)

// AccessResult represents the outcome of [Resolver.CheckAccess].
type AccessResult struct {
	Allowed bool    // True if permitted by a matching rule.
	Rule    *string // Matching rule, or nil.
}

// Resolver evaluates network requests against a rule set.
type Resolver struct {
	rules []Rule
}

// NewResolver creates a [Resolver] with the given rules.
func NewResolver(rules []Rule) *Resolver {
	return &Resolver{rules: rules}
}

// CheckAccess evaluates a (protocol, host, port) tuple against rules.
// host is a domain name or IP (without brackets for IPv6). Default-deny.
func (r *Resolver) CheckAccess(protocol protocol, host string, port uint16) AccessResult {
	lowerHost := strings.ToLower(host)

	// Try to parse the host as an IP address
	parsedIP := net.ParseIP(lowerHost)

	var bestRule *Rule
	bestSpecificity := -1

	for _, rule := range r.rules {
		if !protocolCompatible(rule.protocol, protocol) {
			continue
		}

		if !portMatches(rule.port, port) {
			continue
		}

		specificity := targetSpecificity(&rule, lowerHost, parsedIP)
		if specificity < 0 {
			continue
		}

		if specificity > bestSpecificity {
			bestSpecificity = specificity
			bestRule = &rule
		}
	}

	if bestRule == nil {
		return AccessResult{Allowed: false, Rule: nil}
	}

	allowed := bestRule.protocol == ProtocolHTTP
	rawRule := bestRule.RawRule
	return AccessResult{Allowed: allowed, Rule: &rawRule}
}

// protocolCompatible checks if a rule's protocol matches the request protocol.
// protocolNone matches any protocol (it's a protocol-agnostic deny).
func protocolCompatible(ruleProtocol, requestProtocol protocol) bool {
	if ruleProtocol == protocolNone {
		return true
	}
	return ruleProtocol == requestProtocol
}

func portMatches(rulePort port, requestPort uint16) bool {
	if rulePort.isWildcard {
		return true
	}
	return rulePort.number == requestPort
}

// targetSpecificity returns the specificity of a rule's target match against
// the request. Returns -1 if the target does not match. Higher values are
// more specific.
func targetSpecificity(rule *Rule, lowerHost string, addr net.IP) int {
	switch rule.target.kind {
	case targetDomain:
		if addr != nil {
			// Request is an IP, domain rules don't match IP requests
			return -1
		}
		return domainSpecificity(rule.target, lowerHost)

	case targetIP:
		if addr == nil {
			// Request is a domain, IP rules don't match domain requests
			return -1
		}
		return ipSpecificity(rule.target, addr)

	default:
		return -1
	}
}

// domainSpecificity returns the specificity of a domain rule match.
// Returns -1 if the domain does not match.
// Exact match: label count (always beats wildcard with same suffix).
// Wildcard match: non-wildcard label count
func domainSpecificity(ruleTarget target, host string) int {
	if ruleTarget.wildcard {
		// *.example.com matches exactly one subdomain level
		suffix := ruleTarget.domain[1:] // ".example.com"
		if !strings.HasSuffix(host, suffix) {
			return -1
		}
		// Check that there's exactly one label before the suffix
		prefix := host[:len(host)-len(suffix)]
		if len(prefix) == 0 || strings.Contains(prefix, ".") {
			return -1
		}
		return strings.Count(ruleTarget.domain, ".")
	}

	// Exact match
	if host == ruleTarget.domain {
		return strings.Count(ruleTarget.domain, ".") + 1
	}

	return -1
}

// ipSpecificity returns the specificity of an IP rule match.
// Returns -1 if the IP does not match. Otherwise returns the prefix length.
func ipSpecificity(ruleTarget target, addr net.IP) int {
	// Normalize IPv4-mapped IPv6 to IPv4 for matching
	if v4 := addr.To4(); v4 != nil {
		addr = v4
	}

	if !ruleTarget.ipNet.Contains(addr) {
		return -1
	}

	return ruleTarget.prefixLen
}
