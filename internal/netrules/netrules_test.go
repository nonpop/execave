package netrules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Parse: valid rules ---

func TestParse_ValidHTTPSDomain(t *testing.T) {
	rule, err := ParseAccessRule("https:api.example.com:443")
	require.NoError(t, err)

	assert.Equal(t, ProtocolHTTPS, rule.protocol)
	assert.Equal(t, targetDomain, rule.target.kind)
	assert.Equal(t, "api.example.com", rule.target.domain)
	assert.False(t, rule.target.wildcard)
	assert.Equal(t, uint16(443), rule.port.number)
	assert.False(t, rule.port.isWildcard)
}

func TestParse_ValidHTTPIP(t *testing.T) {
	rule, err := ParseAccessRule("http:192.168.1.50:3000")
	require.NoError(t, err)

	assert.Equal(t, ProtocolHTTP, rule.protocol)
	assert.Equal(t, targetIP, rule.target.kind)
	assert.Equal(t, 32, rule.target.prefixLen)
	assert.Equal(t, uint16(3000), rule.port.number)
}

func TestParse_ValidCIDR(t *testing.T) {
	rule, err := ParseAccessRule("http:10.0.0.0/24:8080")
	require.NoError(t, err)

	assert.Equal(t, ProtocolHTTP, rule.protocol)
	assert.Equal(t, targetIP, rule.target.kind)
	assert.Equal(t, 24, rule.target.prefixLen)
	assert.Equal(t, uint16(8080), rule.port.number)
}

func TestParse_ValidIPv6(t *testing.T) {
	rule, err := ParseAccessRule("https:[::1]:443")
	require.NoError(t, err)

	assert.Equal(t, ProtocolHTTPS, rule.protocol)
	assert.Equal(t, targetIP, rule.target.kind)
	assert.Equal(t, 128, rule.target.prefixLen)
	assert.Equal(t, uint16(443), rule.port.number)
}

func TestParse_ValidIPv6CIDR(t *testing.T) {
	rule, err := ParseAccessRule("https:[2001:db8::]/32:443")
	require.NoError(t, err)

	assert.Equal(t, ProtocolHTTPS, rule.protocol)
	assert.Equal(t, targetIP, rule.target.kind)
	assert.Equal(t, 32, rule.target.prefixLen)
	assert.Equal(t, uint16(443), rule.port.number)
}

func TestParse_ValidWildcardPort(t *testing.T) {
	rule, err := ParseAccessRule("https:example.com:*")
	require.NoError(t, err)

	assert.True(t, rule.port.isWildcard)
}

func TestParse_ValidNoneProtocol(t *testing.T) {
	rule, err := ParseAccessRule("none:evil.com:443")
	require.NoError(t, err)

	assert.Equal(t, protocolNone, rule.protocol)
}

func TestParse_ValidWildcardDomain(t *testing.T) {
	rule, err := ParseAccessRule("https:*.example.com:443")
	require.NoError(t, err)

	assert.Equal(t, targetDomain, rule.target.kind)
	assert.True(t, rule.target.wildcard)
	assert.Equal(t, "*.example.com", rule.target.domain)
}

func TestParse_ValidSingleLabelDomain(t *testing.T) {
	rule, err := ParseAccessRule("http:localhost:3000")
	require.NoError(t, err)

	assert.Equal(t, targetDomain, rule.target.kind)
	assert.Equal(t, "localhost", rule.target.domain)
}

func TestParse_DomainNormalizedToLowercase(t *testing.T) {
	rule, err := ParseAccessRule("https:API.Example.COM:443")
	require.NoError(t, err)

	assert.Equal(t, "api.example.com", rule.target.domain)
}

// --- Parse: invalid rules ---

func TestParse_InvalidAction(t *testing.T) {
	_, err := ParseAccessRule("allow:example.com:443")
	assert.ErrorContains(t, err, "invalid action")
}

func TestParse_MissingPortField(t *testing.T) {
	_, err := ParseAccessRule("https:example.com")
	assert.ErrorContains(t, err, "malformed rule")
}

func TestParse_PortZero(t *testing.T) {
	_, err := ParseAccessRule("https:example.com:0")
	assert.ErrorContains(t, err, "invalid port")
}

func TestParse_PortAboveRange(t *testing.T) {
	_, err := ParseAccessRule("https:example.com:99999")
	assert.ErrorContains(t, err, "invalid port")
}

func TestParse_PortNegative(t *testing.T) {
	_, err := ParseAccessRule("https:example.com:-1")
	assert.ErrorContains(t, err, "invalid port")
}

func TestParse_PortNonNumeric(t *testing.T) {
	_, err := ParseAccessRule("https:example.com:abc")
	assert.ErrorContains(t, err, "invalid port")
}

// --- Parse: target parsing order ---

func TestParse_BracketedIPv6ParsedAsIPv6(t *testing.T) {
	rule, err := ParseAccessRule("https:[::1]:443")
	require.NoError(t, err)

	assert.Equal(t, targetIP, rule.target.kind)
}

func TestParse_CIDRParsedBeforeIP(t *testing.T) {
	rule, err := ParseAccessRule("http:10.0.0.0/24:8080")
	require.NoError(t, err)

	assert.Equal(t, targetIP, rule.target.kind)
	assert.Equal(t, 24, rule.target.prefixLen)
}

func TestParse_BareIPParsedAsExactIP(t *testing.T) {
	rule, err := ParseAccessRule("http:192.168.1.50:3000")
	require.NoError(t, err)

	assert.Equal(t, targetIP, rule.target.kind)
	assert.Equal(t, 32, rule.target.prefixLen)
}

func TestParse_NonIPStringParsedAsDomain(t *testing.T) {
	rule, err := ParseAccessRule("https:api.example.com:443")
	require.NoError(t, err)

	assert.Equal(t, targetDomain, rule.target.kind)
}

func TestParse_InvalidIPFallsThroughToDomainAndFails(t *testing.T) {
	// 123.456.789.0 fails IP parsing, then fails domain validation
	// (all-numeric last label)
	_, err := ParseAccessRule("https:123.456.789.0:443")
	assert.ErrorContains(t, err, "invalid target")
}

// --- Domain pattern validation ---

func TestParse_DomainValidExact(t *testing.T) {
	_, err := ParseAccessRule("https:api.example.com:443")
	assert.NoError(t, err)
}

func TestParse_DomainValidWildcard(t *testing.T) {
	_, err := ParseAccessRule("https:*.example.com:443")
	assert.NoError(t, err)
}

func TestParse_DomainValidSingleLabel(t *testing.T) {
	_, err := ParseAccessRule("http:localhost:3000")
	assert.NoError(t, err)
}

func TestParse_DomainAllNumericTLDRejected(t *testing.T) {
	_, err := ParseAccessRule("https:192.168.1.999:443")
	assert.ErrorContains(t, err, "invalid target")
}

func TestParse_DomainBareWildcardRejected(t *testing.T) {
	_, err := ParseAccessRule("https:*:443")
	assert.ErrorContains(t, err, "invalid domain")
}

func TestParse_DomainDeepWildcardRejected(t *testing.T) {
	_, err := ParseAccessRule("https:*.*.example.com:443")
	assert.ErrorContains(t, err, "invalid domain")
}

func TestParse_DomainNonLeftmostWildcardRejected(t *testing.T) {
	_, err := ParseAccessRule("https:sub.*.example.com:443")
	assert.ErrorContains(t, err, "invalid domain")
}

func TestParse_DomainLabelStartingWithHyphenRejected(t *testing.T) {
	_, err := ParseAccessRule("https:-example.com:443")
	assert.ErrorContains(t, err, "invalid domain")
}

func TestParse_DomainLabelEndingWithHyphenRejected(t *testing.T) {
	_, err := ParseAccessRule("https:example-.com:443")
	assert.ErrorContains(t, err, "invalid domain")
}

func TestParse_DomainLabelTooLong(t *testing.T) {
	long := strings.Repeat("a", 64)
	_, err := ParseAccessRule("https:" + long + ".com:443")
	assert.ErrorContains(t, err, "invalid domain")
}

func TestParse_DomainEmptyLabel(t *testing.T) {
	_, err := ParseAccessRule("https:example..com:443")
	assert.ErrorContains(t, err, "invalid domain")
}

// --- Port validation ---

func TestParse_PortMin(t *testing.T) {
	rule, err := ParseAccessRule("https:example.com:1")
	require.NoError(t, err)
	assert.Equal(t, uint16(1), rule.port.number)
}

func TestParse_PortMax(t *testing.T) {
	rule, err := ParseAccessRule("https:example.com:65535")
	require.NoError(t, err)
	assert.Equal(t, uint16(65535), rule.port.number)
}

func TestParse_PortWildcard(t *testing.T) {
	rule, err := ParseAccessRule("https:example.com:*")
	require.NoError(t, err)
	assert.True(t, rule.port.isWildcard)
}

// --- Config validation ---

func TestValidate_NoDuplicateIdentity(t *testing.T) {
	rules := []AccessRule{
		parseRule(t, "https:example.com:443"),
		parseRule(t, "none:example.com:443"),
	}
	err := ValidateAccessRules(rules)
	assert.ErrorContains(t, err, "duplicate net rule")
}

func TestValidate_DuplicateCIDRIdentity(t *testing.T) {
	rules := []AccessRule{
		parseRule(t, "https:10.0.0.0/24:443"),
		parseRule(t, "none:10.0.0.0/24:443"),
	}
	err := ValidateAccessRules(rules)
	assert.ErrorContains(t, err, "duplicate net rule")
}

func TestValidate_SameTargetDifferentPortsAllowed(t *testing.T) {
	rules := []AccessRule{
		parseRule(t, "https:example.com:443"),
		parseRule(t, "http:example.com:80"),
	}
	err := ValidateAccessRules(rules)
	assert.NoError(t, err)
}

func TestValidate_MixedPortPatternsRejected(t *testing.T) {
	rules := []AccessRule{
		parseRule(t, "https:example.com:*"),
		parseRule(t, "none:example.com:443"),
	}
	err := ValidateAccessRules(rules)
	assert.ErrorContains(t, err, "mixed port patterns")
}

func TestValidate_MixedPortPatternsCIDRRejected(t *testing.T) {
	rules := []AccessRule{
		parseRule(t, "https:10.0.0.0/24:*"),
		parseRule(t, "none:10.0.0.0/24:443"),
	}
	err := ValidateAccessRules(rules)
	assert.ErrorContains(t, err, "mixed port patterns")
}

func TestValidate_DifferentTargetsDifferentPortStylesAllowed(t *testing.T) {
	rules := []AccessRule{
		parseRule(t, "https:example.com:*"),
		parseRule(t, "https:other.com:443"),
	}
	err := ValidateAccessRules(rules)
	assert.NoError(t, err)
}

func TestValidate_Empty(t *testing.T) {
	err := ValidateAccessRules(nil)
	assert.NoError(t, err)
}

// --- IPv6 bracket parsing edge cases ---

func TestParse_IPv6BracketedCIDR(t *testing.T) {
	rule, err := ParseAccessRule("https:[2001:db8::]/32:443")
	require.NoError(t, err)

	assert.Equal(t, targetIP, rule.target.kind)
	assert.Equal(t, 32, rule.target.prefixLen)
}

func TestParse_IPv6MissingClosingBracket(t *testing.T) {
	_, err := ParseAccessRule("https:[::1:443")
	assert.Error(t, err)
}

func TestParse_IPv6InvalidAddress(t *testing.T) {
	_, err := ParseAccessRule("https:[not-an-ip]:443")
	assert.Error(t, err)
}

func TestParse_BracketedIPv4Rejected(t *testing.T) {
	_, err := ParseAccessRule("https:[127.0.0.1]:443")
	assert.ErrorContains(t, err, "invalid IPv6 address")
}

func TestParse_BracketedIPv4CIDRRejected(t *testing.T) {
	_, err := ParseAccessRule("http:[10.0.0.0]/24:8080")
	assert.ErrorContains(t, err, "invalid IPv6 CIDR")
}

func TestParse_EmptyBracketsRejected(t *testing.T) {
	_, err := ParseAccessRule("https:[]:443")
	assert.ErrorContains(t, err, "invalid IPv6 address")
}

func TestParse_BracketedDomainRejected(t *testing.T) {
	_, err := ParseAccessRule("https:[example.com]:443")
	assert.ErrorContains(t, err, "invalid IPv6 address")
}

func TestParse_BracketedIPv4MappedIPv6Accepted(t *testing.T) {
	rule, err := ParseAccessRule("https:[::ffff:127.0.0.1]:443")
	require.NoError(t, err)

	assert.Equal(t, targetIP, rule.target.kind)
	assert.Equal(t, 32, rule.target.prefixLen) // normalized to IPv4
}

// --- helpers ---

func parseRule(t *testing.T, ruleBody string) AccessRule {
	t.Helper()
	rule, err := ParseAccessRule(ruleBody)
	require.NoError(t, err)
	return rule
}
