package netrules

import "net"

// Test-only exports for black-box testing.

type Protocol = protocol

const ProtocolNone = protocolNone

type TargetKind = targetKind

const (
	TargetDomain TargetKind = targetDomain
	TargetIP     TargetKind = targetIP
)

// RuleProtocol returns the rule's protocol.
func RuleProtocol(r Rule) Protocol { return r.protocol }

// RuleTargetKind returns the rule's target kind.
func RuleTargetKind(r Rule) targetKind { return r.target.kind }

// RuleTargetDomain returns the rule's target domain string.
func RuleTargetDomain(r Rule) string { return r.target.domain }

// RuleTargetWildcard returns whether the rule's target is a wildcard domain.
func RuleTargetWildcard(r Rule) bool { return r.target.wildcard }

// RuleTargetIPNet returns the rule's target IP network.
func RuleTargetIPNet(r Rule) *net.IPNet { return r.target.ipNet }

// RuleTargetPrefixLen returns the rule's target CIDR prefix length.
func RuleTargetPrefixLen(r Rule) int { return r.target.prefixLen }

// RulePortIsWildcard returns whether the rule's port is a wildcard.
func RulePortIsWildcard(r Rule) bool { return r.port.isWildcard }

// RulePortNumber returns the rule's port number.
func RulePortNumber(r Rule) uint16 { return r.port.number }

// RuleRawTarget returns the rule's canonical target pattern.
func RuleRawTarget(r Rule) string { return r.rawTarget }

// RuleRawPort returns the rule's raw port string.
func RuleRawPort(r Rule) string { return r.rawPort }
