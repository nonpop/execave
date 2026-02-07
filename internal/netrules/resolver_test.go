package netrules_test

import (
	"testing"

	"github.com/nonpop/execave/internal/netrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Domain matching ---

func TestResolve_ExactDomainMatches(t *testing.T) {
	r := newResolver(t, "https:api.example.com:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "api.example.com", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_ExactDomainCaseInsensitive(t *testing.T) {
	r := newResolver(t, "https:API.Example.COM:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "api.example.com", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_WildcardMatchesOneSubdomainLevel(t *testing.T) {
	r := newResolver(t, "https:*.example.com:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "api.example.com", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_WildcardDoesNotMatchApex(t *testing.T) {
	r := newResolver(t, "https:*.example.com:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "example.com", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_WildcardDoesNotMatchDeepSubdomain(t *testing.T) {
	r := newResolver(t, "https:*.example.com:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "deep.sub.example.com", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_WildcardRespectsDomainBoundary(t *testing.T) {
	r := newResolver(t, "https:*.example.com:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "notexample.com", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_RequestDomainCaseInsensitive(t *testing.T) {
	r := newResolver(t, "https:api.example.com:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "API.EXAMPLE.COM", 443)
	assert.True(t, result.Allowed)
}

// --- IP/CIDR matching ---

func TestResolve_ExactIPv4Matches(t *testing.T) {
	r := newResolver(t, "http:192.168.1.50:3000")
	result := r.Resolve(netrules.ProtocolHTTP, "192.168.1.50", 3000)
	assert.True(t, result.Allowed)
}

func TestResolve_IPv4MappedIPv6MatchesIPv4Rule(t *testing.T) {
	r := newResolver(t, "http:192.168.1.50:3000")
	// ::ffff:192.168.1.50 is the IPv4-mapped IPv6 form; must match the IPv4 rule
	result := r.Resolve(netrules.ProtocolHTTP, "::ffff:192.168.1.50", 3000)
	assert.True(t, result.Allowed)
}

func TestResolve_CIDRMatchesIPInRange(t *testing.T) {
	r := newResolver(t, "http:10.0.0.0/24:*")
	result := r.Resolve(netrules.ProtocolHTTP, "10.0.0.5", 8080)
	assert.True(t, result.Allowed)
}

func TestResolve_CIDRDoesNotMatchIPOutsideRange(t *testing.T) {
	r := newResolver(t, "http:10.0.0.0/24:*")
	result := r.Resolve(netrules.ProtocolHTTP, "10.1.0.5", 8080)
	assert.False(t, result.Allowed)
}

func TestResolve_ExactIPv6Matches(t *testing.T) {
	r := newResolver(t, "https:[::1]:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "::1", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_IPv6CIDRMatchesIPInRange(t *testing.T) {
	r := newResolver(t, "https:[2001:db8::]/32:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "2001:db8::1", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_IPv6CIDRDoesNotMatchIPOutsideRange(t *testing.T) {
	r := newResolver(t, "https:[2001:db8::]/32:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "2001:db9::1", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_IPRuleDoesNotMatchDomain(t *testing.T) {
	r := newResolver(t, "http:127.0.0.1:80")
	result := r.Resolve(netrules.ProtocolHTTP, "localhost", 80)
	assert.False(t, result.Allowed)
}

// --- Resolution: specificity ---

func TestResolve_ExactDomainBeatsWildcard(t *testing.T) {
	r := newResolver(t,
		"https:*.example.com:443",
		"none:evil.example.com:443",
	)
	result := r.Resolve(netrules.ProtocolHTTPS, "evil.example.com", 443)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Rule, "evil.example.com")
}

func TestResolve_WildcardAllowsWhenNoExactDeny(t *testing.T) {
	r := newResolver(t,
		"https:*.example.com:443",
		"none:evil.example.com:443",
	)
	result := r.Resolve(netrules.ProtocolHTTPS, "api.example.com", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_LongerCIDRPrefixBeatsShorter(t *testing.T) {
	r := newResolver(t,
		"http:10.0.0.0/24:*",
		"none:10.0.0.99/32:*",
	)
	result := r.Resolve(netrules.ProtocolHTTP, "10.0.0.99", 8080)
	assert.False(t, result.Allowed)
}

func TestResolve_ShorterCIDRAllowsWhenLongerDoesNotMatch(t *testing.T) {
	r := newResolver(t,
		"http:10.0.0.0/24:*",
		"none:10.0.0.99/32:*",
	)
	result := r.Resolve(netrules.ProtocolHTTP, "10.0.0.5", 8080)
	assert.True(t, result.Allowed)
}

func TestResolve_NoMatchDefaultsDeny(t *testing.T) {
	r := newResolver(t, "https:api.example.com:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "evil.com", 443)
	assert.False(t, result.Allowed)
	assert.Equal(t, "no-matching-rule", result.Rule)
}

// --- Protocol compatibility ---

func TestResolve_HTTPSRuleMatchesCONNECT(t *testing.T) {
	r := newResolver(t, "https:example.com:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "example.com", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_HTTPSRuleDoesNotMatchPlainHTTP(t *testing.T) {
	r := newResolver(t, "https:example.com:443")
	result := r.Resolve(netrules.ProtocolHTTP, "example.com", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_HTTPRuleMatchesPlainHTTP(t *testing.T) {
	r := newResolver(t, "http:example.com:80")
	result := r.Resolve(netrules.ProtocolHTTP, "example.com", 80)
	assert.True(t, result.Allowed)
}

func TestResolve_HTTPRuleDoesNotMatchCONNECT(t *testing.T) {
	r := newResolver(t, "http:example.com:80")
	result := r.Resolve(netrules.ProtocolHTTPS, "example.com", 80)
	assert.False(t, result.Allowed)
}

func TestResolve_NoneRuleMatchesAnyProtocol(t *testing.T) {
	r := newResolver(t, "none:evil.com:443")

	result := r.Resolve(netrules.ProtocolHTTPS, "evil.com", 443)
	assert.False(t, result.Allowed)

	result = r.Resolve(netrules.ProtocolHTTP, "evil.com", 443)
	assert.False(t, result.Allowed)
}

// --- Port matching ---

func TestResolve_ExactPortMatches(t *testing.T) {
	r := newResolver(t, "https:example.com:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "example.com", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_ExactPortDoesNotMatchDifferentPort(t *testing.T) {
	r := newResolver(t, "https:example.com:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "example.com", 8443)
	assert.False(t, result.Allowed)
}

func TestResolve_WildcardPortMatchesAnyPort(t *testing.T) {
	r := newResolver(t, "https:example.com:*")
	result := r.Resolve(netrules.ProtocolHTTPS, "example.com", 8080)
	assert.True(t, result.Allowed)
}

// --- Result.Rule contains matching rule ---

func TestResolve_ResultContainsMatchingRule(t *testing.T) {
	r := newResolver(t, "https:api.example.com:443")
	result := r.Resolve(netrules.ProtocolHTTPS, "api.example.com", 443)
	assert.True(t, result.Allowed)
	assert.Contains(t, result.Rule, "api.example.com")
}

// --- Worked examples from draft ---

func TestResolve_WorkedExampleHTTPSOnly(t *testing.T) {
	r := newResolver(t, "https:api.anthropic.com:443")

	result := r.Resolve(netrules.ProtocolHTTPS, "api.anthropic.com", 443)
	assert.True(t, result.Allowed)

	result = r.Resolve(netrules.ProtocolHTTPS, "evil.com", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_WorkedExampleWildcardWithDeny(t *testing.T) {
	resolver := newResolver(t,
		"https:*.github.com:443",
		"none:evil.github.com:443",
	)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "api.github.com", 443)
	assert.True(t, result.Allowed)

	result = resolver.Resolve(netrules.ProtocolHTTPS, "evil.github.com", 443)
	assert.False(t, result.Allowed)

	// *.github.com does NOT match github.com itself
	result = resolver.Resolve(netrules.ProtocolHTTPS, "github.com", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_WorkedExampleHTTPSvsHTTP(t *testing.T) {
	resolver := newResolver(t,
		"https:example.com:443",
		"http:example.com:80",
	)

	result := resolver.Resolve(netrules.ProtocolHTTPS, "example.com", 443)
	assert.True(t, result.Allowed)

	result = resolver.Resolve(netrules.ProtocolHTTP, "example.com", 80)
	assert.True(t, result.Allowed)

	result = resolver.Resolve(netrules.ProtocolHTTP, "example.com", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_WorkedExampleWildcardPortAllowsAll(t *testing.T) {
	r := newResolver(t, "https:example.com:*")

	result := r.Resolve(netrules.ProtocolHTTPS, "example.com", 443)
	assert.True(t, result.Allowed)

	result = r.Resolve(netrules.ProtocolHTTPS, "example.com", 8080)
	assert.True(t, result.Allowed)
}

func TestResolve_WorkedExampleCIDRWithDeny(t *testing.T) {
	resolver := newResolver(t,
		"http:10.0.0.0/24:*",
		"none:10.0.0.99/32:*",
	)

	result := resolver.Resolve(netrules.ProtocolHTTP, "10.0.0.99", 8080)
	assert.False(t, result.Allowed)

	result = resolver.Resolve(netrules.ProtocolHTTP, "10.0.0.5", 8080)
	assert.True(t, result.Allowed)

	result = resolver.Resolve(netrules.ProtocolHTTP, "10.1.0.5", 8080)
	assert.False(t, result.Allowed)
}

func TestResolve_WorkedExampleExactIPPort(t *testing.T) {
	r := newResolver(t, "http:192.168.1.50:3000")

	result := r.Resolve(netrules.ProtocolHTTP, "192.168.1.50", 3000)
	assert.True(t, result.Allowed)

	result = r.Resolve(netrules.ProtocolHTTP, "192.168.1.50", 4000)
	assert.False(t, result.Allowed)
}

// --- helpers ---

func newResolver(t *testing.T, ruleBodies ...string) *netrules.Resolver {
	t.Helper()
	rules := make([]netrules.Rule, 0, len(ruleBodies))
	for _, body := range ruleBodies {
		rule, err := netrules.Parse(body)
		require.NoError(t, err)
		rule.RawRule = "net:" + body
		rules = append(rules, rule)
	}
	return netrules.NewResolver(rules)
}
