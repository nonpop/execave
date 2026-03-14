package netrules_test

import (
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/netrules"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_DomainNormalizedToLowercase(t *testing.T) {
	rule, err := netrules.ParseAccessRule("http:API.Example.COM:443", "")
	require.NoError(t, err)

	assert.Equal(t, "http:api.example.com:443", rule.Canonical())
}

func TestParse_InvalidIPFallsThroughToDomainAndFails(t *testing.T) {
	// 123.456.789.0 fails IP parsing, then fails domain validation
	// (all-numeric last label)
	_, err := netrules.ParseAccessRule("http:123.456.789.0:443", "")
	assert.ErrorContains(t, err, "invalid domain pattern")
}

func TestParse_DomainAllNumericTLDRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:192.168.1.999:443", "")
	assert.ErrorContains(t, err, "invalid domain pattern")
}

func TestParse_DomainNonLeftmostWildcardRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:sub.*.example.com:443", "")
	assert.ErrorContains(t, err, "invalid domain pattern")
}

func TestParse_DomainLabelStartingWithHyphenRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:-example.com:443", "")
	assert.ErrorContains(t, err, "invalid domain pattern")
}

func TestParse_DomainLabelEndingWithHyphenRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:example-.com:443", "")
	assert.ErrorContains(t, err, "invalid domain pattern")
}

func TestParse_DomainLabelTooLong(t *testing.T) {
	long := strings.Repeat("a", 64)
	_, err := netrules.ParseAccessRule("http:"+long+".com:443", "")
	assert.ErrorContains(t, err, "invalid domain pattern")
}

func TestParse_DomainEmptyLabel(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:example..com:443", "")
	assert.ErrorContains(t, err, "invalid domain pattern")
}

func TestParse_IPv6MissingClosingBracket(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:[::1:443", "")
	assert.ErrorContains(t, err, "missing closing bracket")
}

func TestParse_IPv6InvalidAddress(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:[not-an-ip]:443", "")
	assert.ErrorContains(t, err, "invalid IPv6 address")
}

func TestParse_BracketedIPv4Rejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:[127.0.0.1]:443", "")
	assert.ErrorContains(t, err, "invalid IPv6 address")
}

func TestParse_BracketedIPv4CIDRRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:[10.0.0.0]/24:8080", "")
	assert.ErrorContains(t, err, "invalid IPv6 CIDR")
}

func TestParse_EmptyBracketsRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:[]:443", "")
	assert.ErrorContains(t, err, "invalid IPv6 address")
}

func TestParse_BracketedDomainRejected(t *testing.T) {
	_, err := netrules.ParseAccessRule("http:[example.com]:443", "")
	assert.ErrorContains(t, err, "invalid IPv6 address")
}

func TestParse_BracketedIPv4MappedIPv6Accepted(t *testing.T) {
	// IPv4-mapped IPv6 normalizes to IPv4 /32; Canonical reflects the normalized form.
	rule, err := netrules.ParseAccessRule("http:[::ffff:127.0.0.1]:443", "")
	require.NoError(t, err)

	assert.Equal(t, "http:127.0.0.1/32:443", rule.Canonical())
}

func TestParse_PortMin(t *testing.T) {
	rule, err := netrules.ParseAccessRule("http:example.com:1", "")
	require.NoError(t, err)
	assert.Equal(t, "http:example.com:1", rule.Canonical())
}

func TestParse_PortMax(t *testing.T) {
	rule, err := netrules.ParseAccessRule("http:example.com:65535", "")
	require.NoError(t, err)
	assert.Equal(t, "http:example.com:65535", rule.Canonical())
}

func parseNetRule(t *testing.T, rawRule string) netrules.Rule {
	t.Helper()
	body := strings.TrimPrefix(rawRule, "net:")
	rule, err := netrules.ParseAccessRule(body, "")
	require.NoError(t, err)
	return rule
}

func parseNetRuleFrom(t *testing.T, rawRule, configPath string) netrules.Rule {
	t.Helper()
	body := strings.TrimPrefix(rawRule, "net:")
	rule, err := netrules.ParseAccessRule(body, configPath)
	require.NoError(t, err)
	return rule
}

func TestCanonicalRoundTrip(t *testing.T) {
	cases := []string{
		"http:api.example.com:443",
		"none:evil.com:443",
		"http:*.example.com:443",
		"http:API.EXAMPLE.COM:443",
		"http:192.168.1.50:3000",
		"http:10.0.0.0/24:8080",
		"http:[::1]:443",
		"http:[2001:db8::]/32:443",
		"http:example.com:*",
	}
	for _, tt := range cases {
		t.Run(tt, func(t *testing.T) {
			rule1, err := netrules.ParseAccessRule(tt, "")
			require.NoError(t, err)
			canonical1 := rule1.Canonical()

			rule2, err := netrules.ParseAccessRule(canonical1, "")
			require.NoError(t, err)
			canonical2 := rule2.Canonical()

			assert.Equal(t, canonical1, canonical2)
		})
	}
}

func Test_ParseAccessRule(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		// Net rule syntax
		{"valid IPv6 rule", "http:[::1]:443", ""},
		{"valid IPv6 CIDR rule", "http:[2001:db8::]/32:443", ""},
		{"port zero rejected", "http:example.com:0", "invalid port"},
		{"port above range rejected", "http:example.com:99999", "invalid port"},
		{"non-numeric port rejected", "http:example.com:abc", "invalid port"},

		// Target parsing order
		{"invalid IP falls through to domain validation", "http:123.456.789.0:443", "last label must contain at least one alphabetic character"},
		{"bracketed IPv4 rejected as invalid IPv6", "http:[127.0.0.1]:443", "invalid IPv6 address"},
		{"bracketed IPv4 CIDR rejected as invalid IPv6", "http:[10.0.0.0]/24:8080", "invalid IPv6"},
		{"unclosed bracket rejected", "http:[::1:443", "missing closing bracket"},
		{"empty brackets rejected", "http:[]:443", "invalid IPv6 address"},
		{"bracketed domain rejected", "http:[example.com]:443", "invalid IPv6 address"},
		{"bracketed IPv4-mapped IPv6 accepted", "http:[::ffff:127.0.0.1]:443", ""},
		{"unbracketed IPv6 rejected", "none:::1:80", "IPv6 addresses must be bracketed"},

		// Domain pattern validation
		{"valid wildcard domain", "http:*.example.com:443", ""},
		{"valid single label domain", "http:localhost:3000", ""},
		{"all-numeric TLD rejected", "http:192.168.1.999:443", "last label must contain at least one alphabetic character"},
		{"bare wildcard rejected", "http:*:443", "invalid domain pattern"},
		{"deep wildcard rejected", "http:*.*.example.com:443", "invalid character"},
		{"non-leftmost wildcard rejected", "http:sub.*.example.com:443", "wildcard must be single"},
		{"partial wildcard rejected", "http:sub*.example.com:443", "wildcard must be single"},
		{"label starting with hyphen rejected", "http:-example.com:443", "must not start or end with hyphen"},
		{"trailing dot rejected", "http:example.com.:443", "empty"},
		{"invalid characters rejected", "http:exam_ple.com:443", "invalid character"},
		{"label too long rejected", "http:" + strings.Repeat("a", 64) + ".com:443", "exceeds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := netrules.ParseAccessRule(tt.input, "")
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func Test_ValidateRules(t *testing.T) {
	tests := []struct {
		name    string
		rules   []string
		wantErr string
	}{
		// No duplicate identity — normalization edge cases
		{"single-host CIDR duplicates bare IP", []string{"net:http:127.0.0.1/32:443", "net:none:127.0.0.1:443"}, "duplicate net rule identity"},
		{"IPv4-mapped IPv6 duplicates IPv4", []string{"net:http:[::ffff:127.0.0.1]:443", "net:none:127.0.0.1:443"}, "duplicate net rule identity"},
		{"domain case duplicates", []string{"net:http:Example.COM:443", "net:none:example.com:443"}, "duplicate net rule identity"},
		{"non-canonical CIDR base duplicates canonical", []string{"net:http:10.0.0.5/24:8080", "net:none:10.0.0.0/24:8080"}, "duplicate net rule identity"},
		{"same target different ports allowed", []string{"net:http:example.com:443", "net:http:example.com:80"}, ""},

		// No mixed port patterns
		{"different targets can have different port styles", []string{"net:http:example.com:*", "net:http:other.com:443"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rules []netrules.Rule
			for _, r := range tt.rules {
				rules = append(rules, parseNetRule(t, r))
			}
			err := netrules.ValidateRules(rules)
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func Test_NoDuplicateIdentity_SameFileDuplicateShowsSourceOnce(t *testing.T) {
	rules := []netrules.Rule{
		parseNetRuleFrom(t, "net:http:example.com:443", "/etc/execave.json"),
		parseNetRuleFrom(t, "net:none:example.com:443", "/etc/execave.json"),
	}

	err := netrules.ValidateRules(rules)

	require.ErrorContains(t, err, "duplicate net rule identity")
	require.ErrorContains(t, err, "/etc/execave.json")
	assert.Equal(t, 1, strings.Count(err.Error(), "/etc/execave.json"))
}
