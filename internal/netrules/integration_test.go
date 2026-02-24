package netrules_test

import (
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/netrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseNetRule(t *testing.T, rawRule string) netrules.AccessRule {
	t.Helper()
	body := strings.TrimPrefix(rawRule, "net:")
	rule, err := netrules.ParseAccessRule(body)
	require.NoError(t, err)
	rule.RawRule = rawRule
	return rule
}

// --- Requirement: Net rule syntax ---

func TestIntegration_NetRuleSyntax_ValidHttpsDomainRule(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:api.example.com:443")

	assert.NoError(t, err)
}

func TestIntegration_NetRuleSyntax_ValidHttpIpRule(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:192.168.1.50:3000")

	assert.NoError(t, err)
}

func TestIntegration_NetRuleSyntax_ValidCidrRule(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:10.0.0.0/24:8080")

	assert.NoError(t, err)
}

func TestIntegration_NetRuleSyntax_ValidIpv6Rule(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:[::1]:443")

	assert.NoError(t, err)
}

func TestIntegration_NetRuleSyntax_ValidIpv6CidrRule(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:[2001:db8::]/32:443")

	assert.NoError(t, err)
}

func TestIntegration_NetRuleSyntax_ValidWildcardPortRule(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:example.com:*")

	assert.NoError(t, err)
}

func TestIntegration_NetRuleSyntax_InvalidAction(t *testing.T) {
	_, err := netrules.ParseAccessRule("allow:example.com:443")

	assert.ErrorContains(t, err, "invalid action")
}

func TestIntegration_NetRuleSyntax_MissingPortField(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:example.com")

	assert.ErrorContains(t, err, "malformed rule")
}

func TestIntegration_NetRuleSyntax_InvalidPortNumber(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:example.com:0")

	assert.ErrorContains(t, err, "invalid port")
}

func TestIntegration_NetRuleSyntax_PortAboveRange(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:example.com:99999")

	assert.ErrorContains(t, err, "invalid port")
}

func TestIntegration_NetRuleSyntax_NonNumericPortRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:example.com:abc")

	assert.ErrorContains(t, err, "invalid port")
}

// --- Requirement: Target parsing order ---

func TestIntegration_TargetParsingOrder_BracketedIPv6ParsedAsIPv6(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:[::1]:443")

	assert.NoError(t, err)
}

func TestIntegration_TargetParsingOrder_CIDRParsedBeforeIP(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:10.0.0.0/24:8080")

	assert.NoError(t, err)
}

func TestIntegration_TargetParsingOrder_BareIPParsedAsExactIP(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:192.168.1.50:3000")

	assert.NoError(t, err)
}

func TestIntegration_TargetParsingOrder_NonIPStringParsedAsDomain(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:api.example.com:443")

	assert.NoError(t, err)
}

func TestIntegration_TargetParsingOrder_InvalidIPFallsThroughToDomainValidationAndFails(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:123.456.789.0:443")

	assert.ErrorContains(t, err, "last label must contain at least one alphabetic character")
}

func TestIntegration_TargetParsingOrder_BracketedIPv4RejectedAsInvalidIPv6(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:[127.0.0.1]:443")

	assert.ErrorContains(t, err, "invalid IPv6 address")
}

func TestIntegration_TargetParsingOrder_BracketedIPv4CIDRRejectedAsInvalidIPv6(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:[10.0.0.0]/24:8080")

	assert.ErrorContains(t, err, "invalid IPv6")
}

func TestIntegration_TargetParsingOrder_UnclosedBracketRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:[::1:443")

	assert.ErrorContains(t, err, "missing closing bracket")
}

func TestIntegration_TargetParsingOrder_EmptyBracketsRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:[]:443")

	assert.ErrorContains(t, err, "invalid IPv6 address")
}

func TestIntegration_TargetParsingOrder_BracketedDomainRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:[example.com]:443")

	assert.ErrorContains(t, err, "invalid IPv6 address")
}

func TestIntegration_TargetParsingOrder_BracketedIPv4MappedIPv6Accepted(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:[::ffff:127.0.0.1]:443")

	assert.NoError(t, err)
}

// --- Requirement: Domain pattern validation ---

func TestIntegration_DomainPatternValidation_ValidExactDomain(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:api.example.com:443")

	assert.NoError(t, err)
}

func TestIntegration_DomainPatternValidation_ValidWildcardDomain(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:*.example.com:443")

	assert.NoError(t, err)
}

func TestIntegration_DomainPatternValidation_ValidSingleLabelDomain(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:localhost:3000")

	assert.NoError(t, err)
}

func TestIntegration_DomainPatternValidation_AllNumericTLDRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:192.168.1.999:443")

	assert.ErrorContains(t, err, "last label must contain at least one alphabetic character")
}

func TestIntegration_DomainPatternValidation_BareWildcardRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:*:443")

	assert.ErrorContains(t, err, "invalid domain pattern")
}

func TestIntegration_DomainPatternValidation_DeepWildcardRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:*.*.example.com:443")

	assert.ErrorContains(t, err, "invalid character")
}

func TestIntegration_DomainPatternValidation_NonLeftmostWildcardRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:sub.*.example.com:443")

	assert.ErrorContains(t, err, "wildcard must be single")
}

func TestIntegration_DomainPatternValidation_PartialWildcardRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:sub*.example.com:443")

	assert.ErrorContains(t, err, "wildcard must be single")
}

func TestIntegration_DomainPatternValidation_LabelStartingWithHyphenRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:-example.com:443")

	assert.ErrorContains(t, err, "must not start or end with hyphen")
}

func TestIntegration_DomainPatternValidation_TrailingDotRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:example.com.:443")

	assert.ErrorContains(t, err, "empty label")
}

func TestIntegration_DomainPatternValidation_InvalidCharactersRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("https:exam_ple.com:443")

	assert.ErrorContains(t, err, "invalid character")
}

func TestIntegration_DomainPatternValidation_LabelTooLongRejected(t *testing.T) {
	longLabel := strings.Repeat("a", 64)
	_, err := netrules.ParseAccessRule("https:" + longLabel + ".com:443")

	assert.ErrorContains(t, err, "exceeds")
}

// --- Requirement: Domain matching ---

func TestIntegration_DomainMatching_ExactDomainMatches(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:api.example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "api.example.com", 443)

	assert.True(t, result.Allowed)
}

func TestIntegration_DomainMatching_ExactDomainCaseInsensitive(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:API.Example.COM:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "api.example.com", 443)

	assert.True(t, result.Allowed)
}

func TestIntegration_DomainMatching_WildcardMatchesOneSubdomainLevel(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:*.example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "api.example.com", 443)

	assert.True(t, result.Allowed)
}

func TestIntegration_DomainMatching_WildcardDoesNotMatchApexDomain(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:*.example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "example.com", 443)

	assert.False(t, result.Allowed)
	assert.Equal(t, "no-matching-rule", result.Rule)
}

func TestIntegration_DomainMatching_WildcardDoesNotMatchDeepSubdomain(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:*.example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "deep.sub.example.com", 443)

	assert.False(t, result.Allowed)
	assert.Equal(t, "no-matching-rule", result.Rule)
}

func TestIntegration_DomainMatching_WildcardRespectsDomainBoundary(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:*.example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "notexample.com", 443)

	assert.False(t, result.Allowed)
	assert.Equal(t, "no-matching-rule", result.Rule)
}

// --- Requirement: IP and CIDR matching ---

func TestIntegration_IPAndCIDRMatching_ExactIPv4Matches(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:http:192.168.1.50:3000"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTP, "192.168.1.50", 3000)

	assert.True(t, result.Allowed)
}

func TestIntegration_IPAndCIDRMatching_CIDRRangeMatchesIPWithinRange(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:http:10.0.0.0/24:*"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTP, "10.0.0.5", 8080)

	assert.True(t, result.Allowed)
}

func TestIntegration_IPAndCIDRMatching_CIDRRangeDoesNotMatchIPOutsideRange(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:http:10.0.0.0/24:*"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTP, "10.1.0.5", 8080)

	assert.False(t, result.Allowed)
	assert.Equal(t, "no-matching-rule", result.Rule)
}

func TestIntegration_IPAndCIDRMatching_ExactIPv6Matches(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:[::1]:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "::1", 443)

	assert.True(t, result.Allowed)
}

func TestIntegration_IPAndCIDRMatching_IPv6CIDRMatchesIPWithinRange(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:[2001:db8::]/32:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "2001:db8::1", 443)

	assert.True(t, result.Allowed)
}

func TestIntegration_IPAndCIDRMatching_IPv6CIDRDoesNotMatchIPOutsideRange(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:[2001:db8::]/32:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "2001:db9::1", 443)

	assert.False(t, result.Allowed)
	assert.Equal(t, "no-matching-rule", result.Rule)
}

func TestIntegration_IPAndCIDRMatching_IPRuleDoesNotMatchDomainRequest(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:http:127.0.0.1:80"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTP, "localhost", 80)

	assert.False(t, result.Allowed)
	assert.Equal(t, "no-matching-rule", result.Rule)
}

// --- Requirement: Port matching ---

func TestIntegration_PortMatching_ExactPortMatches(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "example.com", 443)

	assert.True(t, result.Allowed)
}

func TestIntegration_PortMatching_ExactPortDoesNotMatchDifferentPort(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "example.com", 8443)

	assert.False(t, result.Allowed)
	assert.Equal(t, "no-matching-rule", result.Rule)
}

func TestIntegration_PortMatching_WildcardPortMatchesAnyPort(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:example.com:*"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "example.com", 8080)

	assert.True(t, result.Allowed)
}

// --- Requirement: Protocol matching ---

func TestIntegration_ProtocolMatching_HTTPSRuleMatchesHTTPSRequest(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "example.com", 443)

	assert.True(t, result.Allowed)
}

func TestIntegration_ProtocolMatching_HTTPSRuleDoesNotMatchHTTPRequest(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTP, "example.com", 443)

	assert.False(t, result.Allowed)
	assert.Equal(t, "no-matching-rule", result.Rule)
}

func TestIntegration_ProtocolMatching_HTTPRuleMatchesHTTPRequest(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:http:example.com:80"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTP, "example.com", 80)

	assert.True(t, result.Allowed)
}

func TestIntegration_ProtocolMatching_HTTPRuleDoesNotMatchHTTPSRequest(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:http:example.com:80"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "example.com", 80)

	assert.False(t, result.Allowed)
	assert.Equal(t, "no-matching-rule", result.Rule)
}

func TestIntegration_ProtocolMatching_NoneRuleMatchesBothProtocols(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:none:evil.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	httpsResult := resolver.Resolve(netrules.ProtocolHTTPS, "evil.com", 443)
	assert.False(t, httpsResult.Allowed)
	assert.Equal(t, "net:none:evil.com:443", httpsResult.Rule)

	httpResult := resolver.Resolve(netrules.ProtocolHTTP, "evil.com", 443)
	assert.False(t, httpResult.Allowed)
	assert.Equal(t, "net:none:evil.com:443", httpResult.Rule)
}

// --- Requirement: Single-dimension target specificity ---

func TestIntegration_SingleDimensionTargetSpecificity_ExactDomainBeatsWildcard(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:*.example.com:443"),
		parseNetRule(t, "net:none:evil.example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "evil.example.com", 443)

	assert.False(t, result.Allowed)
	assert.Equal(t, "net:none:evil.example.com:443", result.Rule)
}

func TestIntegration_SingleDimensionTargetSpecificity_WildcardAllowsWhenNoExactDeny(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:*.example.com:443"),
		parseNetRule(t, "net:none:evil.example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "api.example.com", 443)

	assert.True(t, result.Allowed)
}

func TestIntegration_SingleDimensionTargetSpecificity_LongerCIDRPrefixBeatsShorter(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:http:10.0.0.0/24:*"),
		parseNetRule(t, "net:none:10.0.0.99/32:*"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTP, "10.0.0.99", 8080)

	assert.False(t, result.Allowed)
	assert.Equal(t, "net:none:10.0.0.99/32:*", result.Rule)
}

func TestIntegration_SingleDimensionTargetSpecificity_ShorterCIDRAllowsWhenLongerDoesNotMatch(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:http:10.0.0.0/24:*"),
		parseNetRule(t, "net:none:10.0.0.99/32:*"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTP, "10.0.0.5", 8080)

	assert.True(t, result.Allowed)
}

func TestIntegration_SingleDimensionTargetSpecificity_NoMatchDefaultsToDeny(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:api.example.com:443"),
	}
	resolver := netrules.NewAccessResolver(rules)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "evil.com", 443)

	assert.False(t, result.Allowed)
	assert.Equal(t, "no-matching-rule", result.Rule)
}

// --- Requirement: No duplicate identity ---

func TestIntegration_NoDuplicateIdentity_SameTargetAndPortWithDifferentActionsRejected(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:example.com:443"),
		parseNetRule(t, "net:none:example.com:443"),
	}

	err := netrules.ValidateAccessRules(rules)

	assert.ErrorContains(t, err, "duplicate net rule identity")
}

func TestIntegration_NoDuplicateIdentity_SameCIDRTargetAndPortWithDifferentActionsRejected(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:10.0.0.0/24:443"),
		parseNetRule(t, "net:none:10.0.0.0/24:443"),
	}

	err := netrules.ValidateAccessRules(rules)

	assert.ErrorContains(t, err, "duplicate net rule identity")
}

func TestIntegration_NoDuplicateIdentity_SingleHostCIDRDuplicatesBareIP(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:127.0.0.1/32:443"),
		parseNetRule(t, "net:none:127.0.0.1:443"),
	}

	err := netrules.ValidateAccessRules(rules)

	assert.ErrorContains(t, err, "duplicate net rule identity")
}

func TestIntegration_NoDuplicateIdentity_IPv4MappedIPv6DuplicatesIPv4(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:[::ffff:127.0.0.1]:443"),
		parseNetRule(t, "net:none:127.0.0.1:443"),
	}

	err := netrules.ValidateAccessRules(rules)

	assert.ErrorContains(t, err, "duplicate net rule identity")
}

func TestIntegration_NoDuplicateIdentity_DomainCaseDuplicates(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:Example.COM:443"),
		parseNetRule(t, "net:none:example.com:443"),
	}

	err := netrules.ValidateAccessRules(rules)

	assert.ErrorContains(t, err, "duplicate net rule identity")
}

func TestIntegration_NoDuplicateIdentity_NonCanonicalCIDRBaseDuplicatesCanonical(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:10.0.0.5/24:8080"),
		parseNetRule(t, "net:none:10.0.0.0/24:8080"),
	}

	err := netrules.ValidateAccessRules(rules)

	assert.ErrorContains(t, err, "duplicate net rule identity")
}

func TestIntegration_NoDuplicateIdentity_SameTargetWithDifferentPortsAllowed(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:example.com:443"),
		parseNetRule(t, "net:http:example.com:80"),
	}

	err := netrules.ValidateAccessRules(rules)

	assert.NoError(t, err)
}

// --- Requirement: No mixed port patterns ---

func TestIntegration_NoMixedPortPatterns_WildcardAndSpecificPortOnSameTargetRejected(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:example.com:*"),
		parseNetRule(t, "net:none:example.com:443"),
	}

	err := netrules.ValidateAccessRules(rules)

	assert.ErrorContains(t, err, "mixed port patterns")
}

func TestIntegration_NoMixedPortPatterns_CIDRWithWildcardAndSpecificPortRejected(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:10.0.0.0/24:*"),
		parseNetRule(t, "net:none:10.0.0.0/24:443"),
	}

	err := netrules.ValidateAccessRules(rules)

	assert.ErrorContains(t, err, "mixed port patterns")
}

func TestIntegration_NoMixedPortPatterns_DifferentTargetsCanHaveDifferentPortStyles(t *testing.T) {
	rules := []netrules.AccessRule{
		parseNetRule(t, "net:https:example.com:*"),
		parseNetRule(t, "net:https:other.com:443"),
	}

	err := netrules.ValidateAccessRules(rules)

	assert.NoError(t, err)
}

// --- Requirement: Log rule syntax ---

func parseNetLogRule(t *testing.T, ruleBody string) netrules.LogRule {
	t.Helper()
	rule, err := netrules.ParseLogRule(ruleBody)
	require.NoError(t, err)
	rule.RawRule = ruleBody
	return rule
}

func TestIntegration_LogRuleSyntax_ValidNologDomainRule(t *testing.T) {
	rule, err := netrules.ParseLogRule("nolog:telemetry.example.com:443")

	require.NoError(t, err)
	assert.False(t, rule.Visible)
}

func TestIntegration_LogRuleSyntax_ValidLogDomainRule(t *testing.T) {
	rule, err := netrules.ParseLogRule("log:api.example.com:443")

	require.NoError(t, err)
	assert.True(t, rule.Visible)
}

func TestIntegration_LogRuleSyntax_ValidNologWildcardDomainRule(t *testing.T) {
	_, err := netrules.ParseLogRule("nolog:*.example.com:*")

	assert.NoError(t, err)
}

func TestIntegration_LogRuleSyntax_ValidNologCIDRRule(t *testing.T) {
	_, err := netrules.ParseLogRule("nolog:10.0.0.0/24:*")

	assert.NoError(t, err)
}

func TestIntegration_LogRuleSyntax_ValidNologIPv6Rule(t *testing.T) {
	_, err := netrules.ParseLogRule("nolog:[::1]:443")

	assert.NoError(t, err)
}

func TestIntegration_LogRuleSyntax_InvalidVisibility(t *testing.T) {
	_, err := netrules.ParseLogRule("hide:example.com:443")

	require.ErrorContains(t, err, "invalid visibility type")
}

func TestIntegration_LogRuleSyntax_MissingPortField(t *testing.T) {
	_, err := netrules.ParseLogRule("nolog:example.com")

	require.ErrorContains(t, err, "malformed rule")
}

func TestIntegration_LogRuleSyntax_InvalidPortNumber(t *testing.T) {
	_, err := netrules.ParseLogRule("nolog:example.com:0")

	require.ErrorContains(t, err, "invalid port")
}

// --- Requirement: Log rule validation ---

func TestIntegration_LogRuleValidation_DuplicateLogRuleIdentityRejected(t *testing.T) {
	rules := []netrules.LogRule{
		parseNetLogRule(t, "nolog:example.com:443"),
		parseNetLogRule(t, "log:example.com:443"),
	}

	err := netrules.ValidateLogRules(rules)

	require.ErrorContains(t, err, "duplicate net log rule identity")
}

func TestIntegration_LogRuleValidation_DomainCaseDuplicatesRejected(t *testing.T) {
	rules := []netrules.LogRule{
		parseNetLogRule(t, "nolog:Example.COM:443"),
		parseNetLogRule(t, "log:example.com:443"),
	}

	err := netrules.ValidateLogRules(rules)

	require.ErrorContains(t, err, "duplicate net log rule identity")
}

func TestIntegration_LogRuleValidation_MixedPortPatternsRejected(t *testing.T) {
	rules := []netrules.LogRule{
		parseNetLogRule(t, "nolog:example.com:*"),
		parseNetLogRule(t, "log:example.com:443"),
	}

	err := netrules.ValidateLogRules(rules)

	require.ErrorContains(t, err, "mixed port patterns")
}

func TestIntegration_LogRuleValidation_SameIdentityInAccessAndLogRulesAllowed(t *testing.T) {
	logRules := []netrules.LogRule{parseNetLogRule(t, "nolog:example.com:443")}

	err := netrules.ValidateLogRules(logRules)

	assert.NoError(t, err)
}

// --- Requirement: Log rule resolution ---

func TestIntegration_LogRuleResolution_NologHidesMatchingHost(t *testing.T) {
	rules := []netrules.LogRule{parseNetLogRule(t, "nolog:telemetry.example.com:443")}
	resolver := netrules.NewLogResolver(rules)

	assert.False(t, resolver.Visible("telemetry.example.com", 443))
}

func TestIntegration_LogRuleResolution_LogOverridesWildcardNolog(t *testing.T) {
	rules := []netrules.LogRule{
		parseNetLogRule(t, "nolog:*.example.com:443"),
		parseNetLogRule(t, "log:api.example.com:443"),
	}
	resolver := netrules.NewLogResolver(rules)

	assert.True(t, resolver.Visible("api.example.com", 443))
}

func TestIntegration_LogRuleResolution_WildcardNologHidesMatchingSubdomain(t *testing.T) {
	rules := []netrules.LogRule{
		parseNetLogRule(t, "nolog:*.example.com:443"),
		parseNetLogRule(t, "log:api.example.com:443"),
	}
	resolver := netrules.NewLogResolver(rules)

	assert.False(t, resolver.Visible("cdn.example.com", 443))
}

func TestIntegration_LogRuleResolution_NoMatchingLogRuleDefaultsToVisible(t *testing.T) {
	rules := []netrules.LogRule{parseNetLogRule(t, "nolog:*.example.com:443")}
	resolver := netrules.NewLogResolver(rules)

	assert.True(t, resolver.Visible("other.com", 443))
}

func TestIntegration_LogRuleResolution_PortSpecificNolog(t *testing.T) {
	rules := []netrules.LogRule{parseNetLogRule(t, "nolog:example.com:443")}
	resolver := netrules.NewLogResolver(rules)

	assert.True(t, resolver.Visible("example.com", 8080))
}

func TestIntegration_LogRuleResolution_WildcardPortNolog(t *testing.T) {
	rules := []netrules.LogRule{parseNetLogRule(t, "nolog:example.com:*")}
	resolver := netrules.NewLogResolver(rules)

	assert.False(t, resolver.Visible("example.com", 8080))
}

func TestIntegration_LogRuleResolution_LongerCIDRPrefixBeatsShorter(t *testing.T) {
	rules := []netrules.LogRule{
		parseNetLogRule(t, "nolog:10.0.0.0/8:*"),
		parseNetLogRule(t, "log:10.0.0.0/24:*"),
	}
	resolver := netrules.NewLogResolver(rules)

	assert.True(t, resolver.Visible("10.0.0.5", 8080))
}
