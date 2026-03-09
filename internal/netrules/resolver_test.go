package netrules_test

import (
	"testing"

	"github.com/nonpop/execave/internal/netrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolve_CaseInsensitive verifies that domain matching is case-insensitive
// on both the rule side (stored as lowercase) and the request side.
func TestResolve_CaseInsensitive(t *testing.T) {
	cases := []struct {
		name    string
		rule    string
		request string
	}{
		{"rule uppercase", "http:API.Example.COM:443", "api.example.com"},
		{"request uppercase", "http:api.example.com:443", "API.EXAMPLE.COM"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newResolver(t, tc.rule)
			result := r.CheckAccess(netrules.ProtocolHTTP, tc.request, 443)
			assert.True(t, result.Allowed)
		})
	}
}

func TestResolve_WildcardMatchesOneSubdomainLevel(t *testing.T) {
	r := newResolver(t, "http:*.example.com:443")
	result := r.CheckAccess(netrules.ProtocolHTTP, "api.example.com", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_WildcardDoesNotMatchApex(t *testing.T) {
	r := newResolver(t, "http:*.example.com:443")
	result := r.CheckAccess(netrules.ProtocolHTTP, "example.com", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_WildcardDoesNotMatchDeepSubdomain(t *testing.T) {
	r := newResolver(t, "http:*.example.com:443")
	result := r.CheckAccess(netrules.ProtocolHTTP, "deep.sub.example.com", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_WildcardRespectsDomainBoundary(t *testing.T) {
	r := newResolver(t, "http:*.example.com:443")
	result := r.CheckAccess(netrules.ProtocolHTTP, "notexample.com", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_IPv4MappedIPv6MatchesIPv4Rule(t *testing.T) {
	r := newResolver(t, "http:192.168.1.50:3000")
	// ::ffff:192.168.1.50 is the IPv4-mapped IPv6 form; must match the IPv4 rule
	result := r.CheckAccess(netrules.ProtocolHTTP, "::ffff:192.168.1.50", 3000)
	assert.True(t, result.Allowed)
}

func TestResolve_ExactIPv6Matches(t *testing.T) {
	r := newResolver(t, "http:[::1]:443")
	result := r.CheckAccess(netrules.ProtocolHTTP, "::1", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_IPv6CIDRMatchesIPInRange(t *testing.T) {
	r := newResolver(t, "http:[2001:db8::]/32:443")
	result := r.CheckAccess(netrules.ProtocolHTTP, "2001:db8::1", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_IPv6CIDRDoesNotMatchIPOutsideRange(t *testing.T) {
	r := newResolver(t, "http:[2001:db8::]/32:443")
	result := r.CheckAccess(netrules.ProtocolHTTP, "2001:db9::1", 443)
	assert.False(t, result.Allowed)
}

func TestResolve_IPRuleDoesNotMatchDomain(t *testing.T) {
	r := newResolver(t, "http:127.0.0.1:80")
	result := r.CheckAccess(netrules.ProtocolHTTP, "localhost", 80)
	assert.False(t, result.Allowed)
}

func TestResolve_ExactDomainBeatsWildcard(t *testing.T) {
	r := newResolver(t,
		"http:*.example.com:443",
		"none:evil.example.com:443",
	)
	result := r.CheckAccess(netrules.ProtocolHTTP, "evil.example.com", 443)
	assert.False(t, result.Allowed)
	require.NotNil(t, result.Rule)
	assert.Contains(t, *result.Rule, "evil.example.com")
}

func TestResolve_WildcardAllowsWhenNoExactDeny(t *testing.T) {
	r := newResolver(t,
		"http:*.example.com:443",
		"none:evil.example.com:443",
	)
	result := r.CheckAccess(netrules.ProtocolHTTP, "api.example.com", 443)
	assert.True(t, result.Allowed)
}

func TestResolve_ResultContainsMatchingRule(t *testing.T) {
	r := newResolver(t, "http:api.example.com:443")
	result := r.CheckAccess(netrules.ProtocolHTTP, "api.example.com", 443)
	assert.True(t, result.Allowed)
	require.NotNil(t, result.Rule)
	assert.Contains(t, *result.Rule, "api.example.com")
}

func TestResolve_WorkedExampleWildcardWithDeny(t *testing.T) {
	resolver := newResolver(t,
		"http:*.github.com:443",
		"none:evil.github.com:443",
	)

	result := resolver.CheckAccess(netrules.ProtocolHTTP, "api.github.com", 443)
	assert.True(t, result.Allowed)

	result = resolver.CheckAccess(netrules.ProtocolHTTP, "evil.github.com", 443)
	assert.False(t, result.Allowed)

	// *.github.com does NOT match github.com itself
	result = resolver.CheckAccess(netrules.ProtocolHTTP, "github.com", 443)
	assert.False(t, result.Allowed)
}

func Test_CheckAccess(t *testing.T) {
	tests := []struct {
		name        string
		rules       []string
		host        string
		port        uint16
		wantAllowed bool
	}{
		// Domain matching
		{"exact domain matches", []string{"http:api.example.com:443"}, "api.example.com", 443, true},
		{"exact domain case-insensitive", []string{"http:API.Example.COM:443"}, "api.example.com", 443, true},
		{"wildcard matches one subdomain level", []string{"http:*.example.com:443"}, "api.example.com", 443, true},
		{"wildcard does not match apex domain", []string{"http:*.example.com:443"}, "example.com", 443, false},
		{"wildcard does not match deep subdomain", []string{"http:*.example.com:443"}, "deep.sub.example.com", 443, false},
		{"wildcard respects domain boundary", []string{"http:*.example.com:443"}, "notexample.com", 443, false},

		// IP and CIDR matching
		{"exact IPv6 matches", []string{"http:[::1]:443"}, "::1", 443, true},
		{"IPv6 CIDR matches IP within range", []string{"http:[2001:db8::]/32:443"}, "2001:db8::1", 443, true},
		{"IPv6 CIDR does not match IP outside range", []string{"http:[2001:db8::]/32:443"}, "2001:db9::1", 443, false},
		{"IP rule does not match domain request", []string{"http:127.0.0.1:80"}, "localhost", 80, false},

		// Target specificity
		{"wildcard allows when no exact deny", []string{"http:*.example.com:443", "none:evil.example.com:443"}, "api.example.com", 443, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newResolver(t, tc.rules...)
			result := r.CheckAccess(netrules.ProtocolHTTP, tc.host, tc.port)
			if tc.wantAllowed {
				assert.True(t, result.Allowed)
			} else {
				assert.False(t, result.Allowed)
				assert.Nil(t, result.Rule)
			}
		})
	}
}

func Test_SingleDimensionTargetSpecificity_ExactDomainBeatsWildcard(t *testing.T) {
	r := newResolver(t,
		"http:*.example.com:443",
		"none:evil.example.com:443",
	)

	result := r.CheckAccess(netrules.ProtocolHTTP, "evil.example.com", 443)

	assert.False(t, result.Allowed)
	require.NotNil(t, result.Rule)
	assert.Equal(t, "none:evil.example.com:443", *result.Rule)
}

func newResolver(t *testing.T, ruleBodies ...string) *netrules.Resolver {
	t.Helper()
	rules := make([]netrules.Rule, 0, len(ruleBodies))
	for _, body := range ruleBodies {
		rule, err := netrules.ParseAccessRule(body, "")
		require.NoError(t, err)
		rules = append(rules, rule)
	}
	return netrules.NewResolver(rules)
}
