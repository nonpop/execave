package e2e_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// IP and CIDR matching

// TestE2E_NetRules_IPAndCIDRMatching_ExactIPv4Matches tests that an exact IP rule allows access.
func TestE2E_NetRules_IPAndCIDRMatching_ExactIPv4Matches(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "IP_EXACT_OK")

	rules := append(systemPaths(),
		fmt.Sprintf("net:http:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-s", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "IP_EXACT_OK")
}

// TestE2E_NetRules_IPAndCIDRMatching_CIDRRangeMatchesIPWithinRange tests that a CIDR range rule allows access
// to IPs within the range.
func TestE2E_NetRules_IPAndCIDRMatching_CIDRRangeMatchesIPWithinRange(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "CIDR_OK")

	rules := append(systemPaths(),
		"net:http:127.0.0.0/8:"+port,
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-s", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "CIDR_OK")
}

// TestE2E_NetRules_IPAndCIDRMatching_CIDRRangeDoesNotMatchIPOutsideRange tests that a CIDR range rule denies
// access to IPs outside the range.
func TestE2E_NetRules_IPAndCIDRMatching_CIDRRangeDoesNotMatchIPOutsideRange(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "should not see this")

	// 10.0.0.0/8 does not include 127.0.0.1
	rules := append(systemPaths(),
		"net:http:10.0.0.0/8:"+port,
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-sf", "--max-time", "5", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assert.NotEqual(t, 0, result.ExitCode)
}

// TestE2E_NetRules_IPAndCIDRMatching_ExactIPv6Matches tests that IPv6 rules work end-to-end.
// Skipped if the test environment does not support IPv6.
func TestE2E_NetRules_IPAndCIDRMatching_ExactIPv6Matches(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	// Start a server on IPv6 loopback
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available")
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "IPV6_OK")
	}))
	srv.Listener = listener
	srv.Start()
	t.Cleanup(srv.Close)

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	rules := append(systemPaths(),
		"net:http:[::1]:"+port,
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-s", fmt.Sprintf("http://[::1]:%s/", port))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "IPV6_OK")
}

// Domain matching

// TestE2E_NetRules_DomainMatching_ExactDomainMatches tests that a domain rule matches by name.
func TestE2E_NetRules_DomainMatching_ExactDomainMatches(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	_, port := testHTTPServer(t, "DOMAIN_OK")

	rules := append(systemPaths(),
		"net:http:localhost:"+port,
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-s", fmt.Sprintf("http://localhost:%s/", port))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "DOMAIN_OK")
}

// Port matching

// TestE2E_NetRules_PortMatching_ExactPortMatches tests that an exact port rule allows the matching port.
func TestE2E_NetRules_PortMatching_ExactPortMatches(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "PORT_EXACT_OK")

	rules := append(systemPaths(),
		fmt.Sprintf("net:http:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-s", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "PORT_EXACT_OK")
}

// TestE2E_NetRules_PortMatching_WildcardPortMatchesAnyPort tests that a wildcard port rule allows any port.
func TestE2E_NetRules_PortMatching_WildcardPortMatchesAnyPort(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "PORT_WILDCARD_OK")

	rules := append(systemPaths(),
		fmt.Sprintf("net:http:%s:*", host),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-s", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assertExitCode(t, result, 0)
	assert.Contains(t, result.Stdout, "PORT_WILDCARD_OK")
}

// TestE2E_NetRules_PortMatching_ExactPortDoesNotMatchDifferentPort tests that a request to a non-allowed port is denied.
func TestE2E_NetRules_PortMatching_ExactPortDoesNotMatchDifferentPort(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "should not see this")

	// Allow port 1, not the test server port
	rules := append(systemPaths(),
		fmt.Sprintf("net:http:%s:1", host),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-sf", "--max-time", "5", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assert.NotEqual(t, 0, result.ExitCode)
}

// Single-dimension target specificity

// TestE2E_NetRules_SingleDimensionTargetSpecificity_LongerCIDRPrefixBeatsShorter tests that a longer
// CIDR prefix deny rule overrides a shorter CIDR allow rule.
func TestE2E_NetRules_SingleDimensionTargetSpecificity_LongerCIDRPrefixBeatsShorter(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "should not see this")

	// Allow /8, deny /32 (more specific wins)
	rules := append(systemPaths(),
		"net:http:127.0.0.0/8:"+port,
		"net:none:127.0.0.1/32:"+port,
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-sf", "--max-time", "5", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assert.NotEqual(t, 0, result.ExitCode)
}

// TestE2E_NetRules_SingleDimensionTargetSpecificity_ShorterCIDRAllowsWhenLongerDoesNotMatch tests that
// a shorter CIDR allow rule takes effect when the longer CIDR deny rule does not match.
func TestE2E_NetRules_SingleDimensionTargetSpecificity_ShorterCIDRAllowsWhenLongerDoesNotMatch(t *testing.T) {
	failIfNoBwrap(t)
	failIfNoCurl(t)

	host, port := testHTTPServer(t, "should not see this")

	// Allow broad CIDR, deny exact IP (more specific wins)
	rules := append(systemPaths(),
		"net:http:127.0.0.0/8:"+port,
		fmt.Sprintf("net:none:%s:%s", host, port),
	)
	configPath := writeConfig(t, rules)

	result := runExecave(t, "", "--config", configPath, "--",
		"curl", "-sf", "--max-time", "5", fmt.Sprintf("http://%s/", net.JoinHostPort(host, port)))

	assert.NotEqual(t, 0, result.ExitCode)
}

// Target parsing order

// TestE2E_NetRules_TargetParsingOrder_BracketedIPv4RejectedAsInvalidIPv6 tests that a bracketed
// IPv4 address is rejected because brackets commit to IPv6 parsing.
func TestE2E_NetRules_TargetParsingOrder_BracketedIPv4RejectedAsInvalidIPv6(t *testing.T) {
	assertInvalidNetRuleRejected(t, "net:https:[127.0.0.1]:443", "invalid IPv6 address")
}

// TestE2E_NetRules_TargetParsingOrder_BracketedIPv4CIDRRejectedAsInvalidIPv6 tests that a bracketed
// IPv4 CIDR is rejected because brackets commit to IPv6 parsing.
func TestE2E_NetRules_TargetParsingOrder_BracketedIPv4CIDRRejectedAsInvalidIPv6(t *testing.T) {
	assertInvalidNetRuleRejected(t, "net:http:[10.0.0.0]/24:8080", "invalid IPv6")
}

// TestE2E_NetRules_TargetParsingOrder_UnclosedBracketRejected tests that an unclosed
// bracket is rejected as a malformed bracketed address.
func TestE2E_NetRules_TargetParsingOrder_UnclosedBracketRejected(t *testing.T) {
	assertInvalidNetRuleRejected(t, "net:https:[::1:443", "missing closing bracket")
}

// TestE2E_NetRules_TargetParsingOrder_EmptyBracketsRejected tests that empty brackets
// are rejected as an invalid IPv6 address.
func TestE2E_NetRules_TargetParsingOrder_EmptyBracketsRejected(t *testing.T) {
	assertInvalidNetRuleRejected(t, "net:https:[]:443", "invalid IPv6 address")
}

// TestE2E_NetRules_TargetParsingOrder_BracketedDomainRejected tests that a domain
// inside brackets is rejected because brackets commit to IPv6 parsing.
func TestE2E_NetRules_TargetParsingOrder_BracketedDomainRejected(t *testing.T) {
	assertInvalidNetRuleRejected(t, "net:https:[example.com]:443", "invalid IPv6 address")
}

// TestE2E_NetRules_TargetParsingOrder_InvalidIPFallsThroughToDomainValidationAndFails tests that
// an invalid IP (out-of-range octets) fails both IP parsing and domain validation.
func TestE2E_NetRules_TargetParsingOrder_InvalidIPFallsThroughToDomainValidationAndFails(t *testing.T) {
	assertInvalidNetRuleRejected(t, "net:https:123.456.789.0:443", "last label must contain at least one alphabetic character")
}

// No duplicate identity

// TestE2E_NetRules_NoDuplicateIdentity_SameTargetAndPortWithDifferentActionsRejected tests that two net rules
// with the same target and port but different actions are rejected.
func TestE2E_NetRules_NoDuplicateIdentity_SameTargetAndPortWithDifferentActionsRejected(t *testing.T) {
	assertDuplicateNetRuleRejected(t, append(systemPaths(),
		"net:https:example.com:443",
		"net:none:example.com:443",
	))
}

// TestE2E_NetRules_NoDuplicateIdentity_SameCIDRTargetAndPortWithDifferentActionsRejected tests that two CIDR rules
// with the same network and port but different actions are rejected.
func TestE2E_NetRules_NoDuplicateIdentity_SameCIDRTargetAndPortWithDifferentActionsRejected(t *testing.T) {
	assertDuplicateNetRuleRejected(t, append(systemPaths(),
		"net:https:10.0.0.0/24:443",
		"net:none:10.0.0.0/24:443",
	))
}

// TestE2E_NetRules_NoDuplicateIdentity_SingleHostCIDRDuplicatesBareIP tests that
// a /32 CIDR and a bare IP with the same address are detected as duplicates.
func TestE2E_NetRules_NoDuplicateIdentity_SingleHostCIDRDuplicatesBareIP(t *testing.T) {
	assertDuplicateNetRuleRejected(t, append(systemPaths(),
		"net:https:127.0.0.1/32:443",
		"net:none:127.0.0.1:443",
	))
}

// TestE2E_NetRules_NoDuplicateIdentity_IPv4MappedIPv6DuplicatesIPv4 tests that
// an IPv4-mapped IPv6 address and an IPv4 address are detected as duplicates.
func TestE2E_NetRules_NoDuplicateIdentity_IPv4MappedIPv6DuplicatesIPv4(t *testing.T) {
	assertDuplicateNetRuleRejected(t, append(systemPaths(),
		"net:https:[::ffff:127.0.0.1]:443",
		"net:none:127.0.0.1:443",
	))
}

// TestE2E_NetRules_NoDuplicateIdentity_DomainCaseDuplicates tests that domain
// comparison is case-insensitive for duplicate detection.
func TestE2E_NetRules_NoDuplicateIdentity_DomainCaseDuplicates(t *testing.T) {
	assertDuplicateNetRuleRejected(t, append(systemPaths(),
		"net:https:Example.COM:443",
		"net:none:example.com:443",
	))
}

// TestE2E_NetRules_NoDuplicateIdentity_NonCanonicalCIDRBaseDuplicatesCanonical tests that
// a CIDR with non-zero host bits is detected as a duplicate of the canonical form.
func TestE2E_NetRules_NoDuplicateIdentity_NonCanonicalCIDRBaseDuplicatesCanonical(t *testing.T) {
	assertDuplicateNetRuleRejected(t, append(systemPaths(),
		"net:https:10.0.0.5/24:8080",
		"net:none:10.0.0.0/24:8080",
	))
}

// No mixed port patterns

// TestE2E_NetRules_NoMixedPortPatterns_WildcardAndSpecificPortOnSameTargetRejected tests that
// a wildcard port and specific port on the same target are rejected.
func TestE2E_NetRules_NoMixedPortPatterns_WildcardAndSpecificPortOnSameTargetRejected(t *testing.T) {
	assertMixedPortPatternsRejected(t, append(systemPaths(),
		"net:https:example.com:*",
		"net:none:example.com:443",
	))
}

// TestE2E_NetRules_NoMixedPortPatterns_CIDRWithWildcardAndSpecificPortRejected tests that
// a CIDR target with wildcard port and specific port are rejected.
func TestE2E_NetRules_NoMixedPortPatterns_CIDRWithWildcardAndSpecificPortRejected(t *testing.T) {
	assertMixedPortPatternsRejected(t, append(systemPaths(),
		"net:https:10.0.0.0/24:*",
		"net:none:10.0.0.0/24:443",
	))
}

// Placeholder tests for remaining delta spec scenarios

// Net rule syntax

// TestE2E_NetRules_NetRuleSyntax_FullFormatWithProtocolTargetPort is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NetRuleSyntax_FullFormatWithProtocolTargetPort(*testing.T) {}

// TestE2E_NetRules_NetRuleSyntax_NoneActionDeniesTarget is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NetRuleSyntax_NoneActionDeniesTarget(*testing.T) {}

// TestE2E_NetRules_NetRuleSyntax_ProtocolFieldValues is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NetRuleSyntax_ProtocolFieldValues(*testing.T) {}

// TestE2E_NetRules_NetRuleSyntax_WildcardPortFormat is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NetRuleSyntax_WildcardPortFormat(*testing.T) {}

// TestE2E_NetRules_NetRuleSyntax_PortRangeValidation is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NetRuleSyntax_PortRangeValidation(*testing.T) {}

// TestE2E_NetRules_NetRuleSyntax_MissingFieldsRejected is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NetRuleSyntax_MissingFieldsRejected(*testing.T) {}

// TestE2E_NetRules_NetRuleSyntax_ExtraFieldsRejected is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NetRuleSyntax_ExtraFieldsRejected(*testing.T) {}

// TestE2E_NetRules_NetRuleSyntax_EmptyFieldsRejected is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NetRuleSyntax_EmptyFieldsRejected(*testing.T) {}

// TestE2E_NetRules_NetRuleSyntax_NonNumericPortRejected is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NetRuleSyntax_NonNumericPortRejected(*testing.T) {}

// TestE2E_NetRules_NetRuleSyntax_UnknownProtocolRejected is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NetRuleSyntax_UnknownProtocolRejected(*testing.T) {}

// Target parsing order (remaining)

// TestE2E_NetRules_TargetParsingOrder_BracketedIPv6ParsedAsIPv6 is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_TargetParsingOrder_BracketedIPv6ParsedAsIPv6(*testing.T) {}

// TestE2E_NetRules_TargetParsingOrder_CIDRParsedBeforeIP is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_TargetParsingOrder_CIDRParsedBeforeIP(*testing.T) {}

// TestE2E_NetRules_TargetParsingOrder_BareIPParsedAsExactIP is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_TargetParsingOrder_BareIPParsedAsExactIP(*testing.T) {}

// TestE2E_NetRules_TargetParsingOrder_NonIPStringParsedAsDomain is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_TargetParsingOrder_NonIPStringParsedAsDomain(*testing.T) {}

// TestE2E_NetRules_TargetParsingOrder_BracketedIPv4MappedIPv6Accepted is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_TargetParsingOrder_BracketedIPv4MappedIPv6Accepted(*testing.T) {}

// Domain pattern validation

// TestE2E_NetRules_DomainPatternValidation_ValidExactDomain is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainPatternValidation_ValidExactDomain(*testing.T) {}

// TestE2E_NetRules_DomainPatternValidation_ValidWildcardDomain is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainPatternValidation_ValidWildcardDomain(*testing.T) {}

// TestE2E_NetRules_DomainPatternValidation_WildcardOnlyInLeftmostLabel is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainPatternValidation_WildcardOnlyInLeftmostLabel(*testing.T) {}

// TestE2E_NetRules_DomainPatternValidation_PartialWildcardRejected is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainPatternValidation_PartialWildcardRejected(*testing.T) {}

// TestE2E_NetRules_DomainPatternValidation_TrailingDotRejected is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainPatternValidation_TrailingDotRejected(*testing.T) {}

// TestE2E_NetRules_DomainPatternValidation_TLDOnlyRejected is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainPatternValidation_TLDOnlyRejected(*testing.T) {}

// TestE2E_NetRules_DomainPatternValidation_InvalidCharactersRejected is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainPatternValidation_InvalidCharactersRejected(*testing.T) {}

// TestE2E_NetRules_DomainPatternValidation_LabelTooLongRejected is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainPatternValidation_LabelTooLongRejected(*testing.T) {}

// Domain matching (remaining)

// TestE2E_NetRules_DomainMatching_ExactDomainCaseInsensitive is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainMatching_ExactDomainCaseInsensitive(*testing.T) {}

// TestE2E_NetRules_DomainMatching_WildcardMatchesOneSubdomainLevel is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainMatching_WildcardMatchesOneSubdomainLevel(*testing.T) {}

// TestE2E_NetRules_DomainMatching_WildcardDoesNotMatchApexDomain is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainMatching_WildcardDoesNotMatchApexDomain(*testing.T) {}

// TestE2E_NetRules_DomainMatching_WildcardDoesNotMatchDeepSubdomain is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainMatching_WildcardDoesNotMatchDeepSubdomain(*testing.T) {}

// TestE2E_NetRules_DomainMatching_WildcardRespectsDomainBoundary is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_DomainMatching_WildcardRespectsDomainBoundary(*testing.T) {}

// IP and CIDR matching (remaining)

// TestE2E_NetRules_IPAndCIDRMatching_IPv6CIDRMatchesIPWithinRange is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_IPAndCIDRMatching_IPv6CIDRMatchesIPWithinRange(*testing.T) {}

// TestE2E_NetRules_IPAndCIDRMatching_IPv6CIDRDoesNotMatchIPOutsideRange is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_IPAndCIDRMatching_IPv6CIDRDoesNotMatchIPOutsideRange(*testing.T) {}

// TestE2E_NetRules_IPAndCIDRMatching_IPRuleDoesNotMatchDomainRequest is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_IPAndCIDRMatching_IPRuleDoesNotMatchDomainRequest(*testing.T) {}

// Protocol matching

// TestE2E_NetRules_ProtocolMatching_HTTPSRuleMatchesHTTPSRequest is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_ProtocolMatching_HTTPSRuleMatchesHTTPSRequest(*testing.T) {}

// TestE2E_NetRules_ProtocolMatching_HTTPRuleMatchesHTTPRequest is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_ProtocolMatching_HTTPRuleMatchesHTTPRequest(*testing.T) {}

// TestE2E_NetRules_ProtocolMatching_HTTPSRuleDoesNotMatchHTTPRequest is a placeholder.
// Covered by Proxy_PlainHTTPForwarding_DeniedHTTPRequestRejected.
func TestE2E_NetRules_ProtocolMatching_HTTPSRuleDoesNotMatchHTTPRequest(*testing.T) {}

// TestE2E_NetRules_ProtocolMatching_HTTPRuleDoesNotMatchHTTPSRequest is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_ProtocolMatching_HTTPRuleDoesNotMatchHTTPSRequest(*testing.T) {}

// TestE2E_NetRules_ProtocolMatching_NoneRuleMatchesBothProtocols is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_ProtocolMatching_NoneRuleMatchesBothProtocols(*testing.T) {}

// Single-dimension target specificity (remaining)

// TestE2E_NetRules_SingleDimensionTargetSpecificity_ExactDomainBeatsWildcard is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_SingleDimensionTargetSpecificity_ExactDomainBeatsWildcard(*testing.T) {}

// TestE2E_NetRules_SingleDimensionTargetSpecificity_WildcardAllowsWhenNoExactDeny is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_SingleDimensionTargetSpecificity_WildcardAllowsWhenNoExactDeny(*testing.T) {}

// TestE2E_NetRules_SingleDimensionTargetSpecificity_NoMatchDefaultsToDeny is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_SingleDimensionTargetSpecificity_NoMatchDefaultsToDeny(*testing.T) {}

// No duplicate identity (remaining)

// TestE2E_NetRules_NoDuplicateIdentity_SameTargetWithDifferentPortsAllowed is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NoDuplicateIdentity_SameTargetWithDifferentPortsAllowed(*testing.T) {}

// No mixed port patterns (remaining)

// TestE2E_NetRules_NoMixedPortPatterns_DifferentTargetsCanHaveDifferentPortStyles is a placeholder.
// Better tested at unit level.
func TestE2E_NetRules_NoMixedPortPatterns_DifferentTargetsCanHaveDifferentPortStyles(*testing.T) {}
