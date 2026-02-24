package netrules

import (
	"net"
	"strings"
)

// ResolveResult represents the outcome of resolving a network request against rules.
type ResolveResult struct {
	// Allowed is true if the request is permitted by a matching rule.
	Allowed bool
	// Rule is the raw rule string that matched, or "no-matching-rule" if no rule matched.
	Rule string
}

// AccessResolver evaluates network requests against a set of net access rules.
type AccessResolver struct {
	rules []AccessRule
}

// NewAccessResolver creates a new AccessResolver from the given net rules.
func NewAccessResolver(rules []AccessRule) *AccessResolver {
	return &AccessResolver{rules: rules}
}

// Resolve evaluates a request against the rules and returns the result.
// host is the domain name or IP address from the request (without brackets for IPv6).
// port is the numeric port from the request.
//
// Resolution uses single-dimension target specificity:
//   - Domains: exact match beats wildcard
//   - IPs: longer CIDR prefix beats shorter
//   - Default: deny
func (r *AccessResolver) Resolve(protocol protocol, host string, port uint16) ResolveResult {
	lowerHost := strings.ToLower(host)

	// Try to parse the host as an IP address
	parsedIP := net.ParseIP(lowerHost)

	var bestRule *AccessRule
	bestSpecificity := -1

	for i := range r.rules {
		rule := &r.rules[i]

		if !protocolCompatible(rule.protocol, protocol) {
			continue
		}

		if !portMatches(rule.port, port) {
			continue
		}

		specificity := targetSpecificity(rule, lowerHost, parsedIP)
		if specificity < 0 {
			continue
		}

		if specificity > bestSpecificity {
			bestSpecificity = specificity
			bestRule = rule
		}
	}

	if bestRule == nil {
		return ResolveResult{Allowed: false, Rule: "no-matching-rule"}
	}

	allowed := bestRule.protocol != protocolNone
	return ResolveResult{Allowed: allowed, Rule: bestRule.RawRule}
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
//
// For domains: exact match returns label count + 1, wildcard returns label count.
// For IPs: returns CIDR prefix length.
func targetSpecificity(rule *AccessRule, lowerHost string, addr net.IP) int {
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
// Exact match: label count + 1 (always beats wildcard with same suffix).
// Wildcard match: label count of the wildcard pattern.
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
		return strings.Count(ruleTarget.domain, ".") + 1
	}

	// Exact match
	if host == ruleTarget.domain {
		labelCount := strings.Count(ruleTarget.domain, ".") + 1
		return labelCount + 1
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
