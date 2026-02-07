package netrules_test

import (
	"strings"
	"testing"

	"github.com/nonpop/execave/internal/netrules"
	"github.com/stretchr/testify/assert"
)

//nolint:funlen
func FuzzParse(f *testing.F) {
	// Valid seeds
	f.Add("https:api.example.com:443")
	f.Add("http:192.168.1.50:3000")
	f.Add("http:10.0.0.0/24:8080")
	f.Add("https:[::1]:443")
	f.Add("https:[2001:db8::]/32:443")
	f.Add("https:example.com:*")
	f.Add("none:evil.com:443")
	f.Add("https:*.example.com:443")
	f.Add("http:localhost:3000")

	// Invalid seeds
	f.Add("allow:example.com:443")
	f.Add("https:example.com")
	f.Add("https:example.com:0")
	f.Add("https:example.com:99999")
	f.Add("https:*:443")
	f.Add("https:*.*.example.com:443")
	f.Add("https:-example.com:443")
	f.Add("")
	f.Add(":")
	f.Add("::")
	f.Add("https:123.456.789.0:443")
	f.Add("https:[not-an-ip]:443")
	f.Add("https:[::1:443")

	f.Fuzz(func(t *testing.T, input string) {
		rule, err := netrules.Parse(input)
		if err != nil {
			return
		}

		// Protocol must be a known allow/deny value.
		assert.Contains(t, []netrules.Protocol{
			netrules.ProtocolHTTPS,
			netrules.ProtocolHTTP,
			netrules.ProtocolNone,
		}, netrules.RuleProtocol(rule))

		// Port: wildcard and number are mutually exclusive.
		if netrules.RulePortIsWildcard(rule) {
			assert.Equal(t, uint16(0), netrules.RulePortNumber(rule))
		} else {
			assert.NotZero(t, netrules.RulePortNumber(rule))
		}

		assert.NotEmpty(t, netrules.RuleRawTarget(rule))
		assert.NotEmpty(t, netrules.RuleRawPort(rule))

		// Target-kind-specific invariants.
		switch netrules.RuleTargetKind(rule) {
		case netrules.TargetDomain:
			assert.NotEmpty(t, netrules.RuleTargetDomain(rule))
			// Domain must be lowercased.
			assert.Equal(t, strings.ToLower(netrules.RuleTargetDomain(rule)), netrules.RuleTargetDomain(rule))
			if netrules.RuleTargetWildcard(rule) {
				assert.True(t, strings.HasPrefix(netrules.RuleTargetDomain(rule), "*."))
			} else {
				assert.NotContains(t, netrules.RuleTargetDomain(rule), "*")
			}
			assert.Nil(t, netrules.RuleTargetIPNet(rule))

		case netrules.TargetIP:
			assert.NotNil(t, netrules.RuleTargetIPNet(rule))
			ones, bits := netrules.RuleTargetIPNet(rule).Mask.Size()
			// PrefixLen must match IPNet mask.
			assert.Equal(t, ones, netrules.RuleTargetPrefixLen(rule))
			if bits == 32 {
				assert.LessOrEqual(t, netrules.RuleTargetPrefixLen(rule), 32)
			} else {
				assert.LessOrEqual(t, netrules.RuleTargetPrefixLen(rule), 128)
			}
			assert.Empty(t, netrules.RuleTargetDomain(rule))
			assert.False(t, netrules.RuleTargetWildcard(rule))
		}
	})
}

func FuzzResolve(f *testing.F) {
	f.Add("api.example.com", uint16(443), true)
	f.Add("evil.com", uint16(443), true)
	f.Add("192.168.1.50", uint16(3000), false)
	f.Add("10.0.0.5", uint16(8080), false)
	f.Add("::1", uint16(443), true)
	f.Add("localhost", uint16(80), false)
	f.Add("", uint16(0), true)
	f.Add("EXAMPLE.COM", uint16(443), true)

	ruleSpecs := []string{
		"https:*.example.com:443",
		"none:evil.example.com:443",
		"http:10.0.0.0/24:*",
		"none:10.0.0.99/32:*",
		"https:[::1]:443",
		"http:localhost:3000",
	}

	rules := make([]netrules.Rule, len(ruleSpecs))
	validRuleStrings := make(map[string]netrules.Protocol)
	for i, spec := range ruleSpecs {
		rules[i] = mustParse(f, spec)
		validRuleStrings[rules[i].RawRule] = netrules.RuleProtocol(rules[i])
	}
	resolver := netrules.NewResolver(rules)

	f.Fuzz(func(t *testing.T, host string, port uint16, isHTTPS bool) {
		protocol := netrules.ProtocolHTTP
		if isHTTPS {
			protocol = netrules.ProtocolHTTPS
		}
		result := resolver.Resolve(protocol, host, port)

		// Allowed results must cite an actual non-none rule.
		if result.Allowed {
			assert.NotEqual(t, "no-matching-rule", result.Rule)
			ruleProto, ok := validRuleStrings[result.Rule]
			assert.True(t, ok)
			if ok {
				assert.NotEqual(t, netrules.ProtocolNone, ruleProto)
			}
		}

		// Denied results must cite either no-matching-rule or a none rule.
		if !result.Allowed {
			if result.Rule != "no-matching-rule" {
				ruleProto, ok := validRuleStrings[result.Rule]
				assert.True(t, ok)
				if ok {
					assert.Equal(t, netrules.ProtocolNone, ruleProto)
				}
			}
		}

		// Determinism: same input must give the same result.
		result2 := resolver.Resolve(protocol, host, port)
		assert.Equal(t, result, result2)
	})
}

func mustParse(f *testing.F, ruleBody string) netrules.Rule {
	f.Helper()
	rule, err := netrules.Parse(ruleBody)
	if err != nil {
		f.Fatalf("parse rule %q: %v", ruleBody, err)
	}
	rule.RawRule = "net:" + ruleBody
	return rule
}
