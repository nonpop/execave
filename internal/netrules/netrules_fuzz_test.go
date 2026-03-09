package netrules

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

//nolint:funlen
func FuzzParse(f *testing.F) {
	// Valid seeds
	f.Add("http:api.example.com:443")
	f.Add("http:192.168.1.50:3000")
	f.Add("http:10.0.0.0/24:8080")
	f.Add("http:[::1]:443")
	f.Add("http:[2001:db8::]/32:443")
	f.Add("http:example.com:*")
	f.Add("none:evil.com:443")
	f.Add("http:*.example.com:443")
	f.Add("http:localhost:3000")

	// Invalid seeds
	f.Add("allow:example.com:443")
	f.Add("https:example.com:443")
	f.Add("http:example.com")
	f.Add("http:example.com:0")
	f.Add("http:example.com:99999")
	f.Add("http:*:443")
	f.Add("http:*.*.example.com:443")
	f.Add("http:-example.com:443")
	f.Add("")
	f.Add(":")
	f.Add("::")
	f.Add("http:123.456.789.0:443")
	f.Add("http:[not-an-ip]:443")
	f.Add("http:[::1:443")

	f.Fuzz(func(t *testing.T, input string) {
		rule, err := ParseAccessRule(input, "")
		if err != nil {
			return
		}

		// Protocol must be a known allow/deny value.
		assert.Contains(t, []protocol{
			ProtocolHTTP,
			protocolNone,
		}, rule.protocol)

		// Port: wildcard and number are mutually exclusive.
		if rule.port.isWildcard {
			assert.Equal(t, uint16(0), rule.port.number)
		} else {
			assert.NotZero(t, rule.port.number)
		}

		assert.NotEmpty(t, rule.canonicalTarget)
		assert.NotEmpty(t, rule.canonicalPort)

		// Target-kind-specific invariants.
		switch rule.target.kind {
		case targetDomain:
			assert.NotEmpty(t, rule.target.domain)
			// Domain must be lowercased.
			assert.Equal(t, strings.ToLower(rule.target.domain), rule.target.domain)
			if rule.target.wildcard {
				assert.True(t, strings.HasPrefix(rule.target.domain, "*."))
			} else {
				assert.NotContains(t, rule.target.domain, "*")
			}
			assert.Nil(t, rule.target.ipNet)

		case targetIP:
			assert.NotNil(t, rule.target.ipNet)
			ones, bits := rule.target.ipNet.Mask.Size()
			// PrefixLen must match IPNet mask.
			assert.Equal(t, ones, rule.target.prefixLen)
			if bits == 32 {
				assert.LessOrEqual(t, rule.target.prefixLen, 32)
			} else {
				assert.LessOrEqual(t, rule.target.prefixLen, 128)
			}
			assert.Empty(t, rule.target.domain)
			assert.False(t, rule.target.wildcard)
		}
	})
}

func FuzzResolve(f *testing.F) {
	f.Add("api.example.com", uint16(443))
	f.Add("evil.com", uint16(443))
	f.Add("192.168.1.50", uint16(3000))
	f.Add("10.0.0.5", uint16(8080))
	f.Add("::1", uint16(443))
	f.Add("localhost", uint16(80))
	f.Add("", uint16(0))
	f.Add("EXAMPLE.COM", uint16(443))

	ruleSpecs := []string{
		"http:*.example.com:443",
		"none:evil.example.com:443",
		"http:10.0.0.0/24:*",
		"none:10.0.0.99/32:*",
		"http:[::1]:443",
		"http:localhost:3000",
	}

	rules := make([]Rule, len(ruleSpecs))
	validRuleStrings := make(map[string]protocol)
	for i, spec := range ruleSpecs {
		rules[i] = mustParse(f, spec)
		validRuleStrings[rules[i].RawRule] = rules[i].protocol
	}
	resolver := NewResolver(rules)

	f.Fuzz(func(t *testing.T, host string, port uint16) {
		result := resolver.CheckAccess(ProtocolHTTP, host, port)

		// Allowed results must cite an actual non-none rule.
		if result.Allowed {
			assert.NotNil(t, result.Rule)
			if result.Rule != nil {
				ruleProto, ok := validRuleStrings[*result.Rule]
				assert.True(t, ok)
				if ok {
					assert.NotEqual(t, protocolNone, ruleProto)
				}
			}
		}

		// Denied results must cite either no rule or a none rule.
		if !result.Allowed {
			if result.Rule != nil {
				ruleProto, ok := validRuleStrings[*result.Rule]
				assert.True(t, ok)
				if ok {
					assert.Equal(t, protocolNone, ruleProto)
				}
			}
		}

		// Determinism: same input must give the same result.
		result2 := resolver.CheckAccess(ProtocolHTTP, host, port)
		assert.Equal(t, result, result2)
	})
}

func mustParse(f *testing.F, ruleBody string) Rule {
	f.Helper()
	rule, err := ParseAccessRule(ruleBody, "")
	if err != nil {
		f.Fatalf("parse rule %q: %v", ruleBody, err)
	}
	return rule
}
