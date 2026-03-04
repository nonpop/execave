# Net Rules Capability

## Purpose

The net-rules capability handles parsing, validation, and resolution of network access control rules. It defines the syntax for network rules, validates target patterns (domains, IPs, CIDRs) and port specifications, enforces single-dimension target specificity for rule resolution, and ensures fail-closed behavior through validation.

## Requirements

### Requirement: Net rule syntax

The system SHALL parse each net rule body matching the pattern `<action>:<target>:<port>` where:
- `<action>` is one of `http`, `none`
- `<target>` is a domain pattern, IPv4 address/CIDR, or bracketed IPv6 address/CIDR
- `<port>` is a numeric port (`1`–`65535`) or wildcard `*`

Invalid rules SHALL be rejected with an error.

#### Scenario: Valid HTTP domain rule
- **WHEN** parsing rule body `http:api.example.com:443`
- **THEN** parsing succeeds

#### Scenario: Valid HTTP IP rule
- **WHEN** parsing rule body `http:192.168.1.50:3000`
- **THEN** parsing succeeds

#### Scenario: Valid CIDR rule
- **WHEN** parsing rule body `http:10.0.0.0/24:8080`
- **THEN** parsing succeeds

#### Scenario: Valid IPv6 rule
- **WHEN** parsing rule body `http:[::1]:443`
- **THEN** parsing succeeds

#### Scenario: Valid IPv6 CIDR rule
- **WHEN** parsing rule body `http:[2001:db8::]/32:443`
- **THEN** parsing succeeds

#### Scenario: Valid wildcard port rule
- **WHEN** parsing rule body `http:example.com:*`
- **THEN** parsing succeeds

#### Scenario: Invalid action
- **WHEN** parsing rule body `allow:example.com:443`
- **THEN** parsing returns error containing "invalid action"

#### Scenario: HTTPS action rejected
- **WHEN** parsing rule body `https:example.com:443`
- **THEN** parsing returns error containing "invalid action"

#### Scenario: Missing port field
- **WHEN** parsing rule body `http:example.com`
- **THEN** parsing returns error containing "malformed rule"

#### Scenario: Invalid port number
- **WHEN** parsing rule body `http:example.com:0`
- **THEN** parsing returns error containing "invalid port"

#### Scenario: Port above range
- **WHEN** parsing rule body `http:example.com:99999`
- **THEN** parsing returns error containing "invalid port"

#### Scenario: Non-numeric port rejected
- **WHEN** parsing rule body `http:example.com:abc`
- **THEN** parsing returns error containing "invalid port"

### Requirement: Target parsing order

The target field SHALL be parsed in the following order:
1. If it starts with `[`, parse as bracketed IPv6 — extract address between `[` and `]`, with optional `/N` CIDR suffix after the closing bracket
2. Attempt `net.ParseCIDR(target)` — if it succeeds, classify as CIDR
3. Attempt `net.ParseIP(target)` — if it succeeds, classify as exact IP (implicit `/32` or `/128`)
4. Otherwise, validate as a domain pattern

Invalid targets that fail all parsing steps SHALL be rejected with an error.

#### Scenario: Bracketed IPv6 parsed as IPv6
- **WHEN** parsing rule body `http:[::1]:443`
- **THEN** parsing succeeds

#### Scenario: CIDR parsed before IP
- **WHEN** parsing rule body `http:10.0.0.0/24:8080`
- **THEN** parsing succeeds

#### Scenario: Bare IP parsed as exact IP
- **WHEN** parsing rule body `http:192.168.1.50:3000`
- **THEN** parsing succeeds

#### Scenario: Non-IP string parsed as domain
- **WHEN** parsing rule body `http:api.example.com:443`
- **THEN** parsing succeeds

#### Scenario: Invalid IP falls through to domain validation and fails
- **WHEN** parsing rule body `http:123.456.789.0:443`
- **THEN** parsing returns error containing "last label must contain at least one alphabetic character"

#### Scenario: Bracketed IPv4 rejected as invalid IPv6
- **WHEN** parsing rule body `http:[127.0.0.1]:443`
- **THEN** parsing returns error containing "invalid IPv6 address"

#### Scenario: Bracketed IPv4 CIDR rejected as invalid IPv6
- **WHEN** parsing rule body `http:[10.0.0.0]/24:8080`
- **THEN** parsing returns error containing "invalid IPv6"

#### Scenario: Unclosed bracket rejected
- **WHEN** parsing rule body `http:[::1:443`
- **THEN** parsing returns error containing "missing closing bracket"

#### Scenario: Empty brackets rejected
- **WHEN** parsing rule body `http:[]:443`
- **THEN** parsing returns error containing "invalid IPv6 address"

#### Scenario: Bracketed domain rejected
- **WHEN** parsing rule body `http:[example.com]:443`
- **THEN** parsing returns error containing "invalid IPv6 address"

#### Scenario: Bracketed IPv4-mapped IPv6 accepted
- **WHEN** parsing rule body `http:[::ffff:127.0.0.1]:443`
- **THEN** parsing succeeds

#### Scenario: Unbracketed IPv6 rejected
- **WHEN** parsing rule body `none:::1:80`
- **THEN** parsing returns error containing "IPv6 addresses must be bracketed"

### Requirement: Domain pattern validation

Domain targets SHALL be validated per RFC 1123. Single-label domains (e.g., `localhost`) are valid. A single wildcard prefix `*.` in the leftmost position is allowed, where `*` replaces exactly one label. Multiple wildcards (e.g., `*.*.example.com`) or wildcards in non-leftmost positions (e.g., `sub.*.example.com`) are invalid. Partial wildcards (e.g., `sub*.example.com`) are also invalid. The last label SHALL contain at least one alphabetic character (all-numeric labels are rejected, preventing misclassification of invalid IP addresses as domains). Labels SHALL contain only alphanumeric characters and hyphens, SHALL NOT start or end with a hyphen, and SHALL NOT exceed 63 characters. Trailing dots are rejected (they produce an empty label).

#### Scenario: Valid exact domain
- **WHEN** parsing rule body `http:api.example.com:443`
- **THEN** parsing succeeds

#### Scenario: Valid wildcard domain
- **WHEN** parsing rule body `http:*.example.com:443`
- **THEN** parsing succeeds

#### Scenario: Valid single-label domain
- **WHEN** parsing rule body `http:localhost:3000`
- **THEN** parsing succeeds

#### Scenario: All-numeric TLD rejected
- **WHEN** parsing rule body `http:192.168.1.999:443`
- **THEN** parsing returns error containing "last label must contain at least one alphabetic character"

#### Scenario: Bare wildcard rejected
- **WHEN** parsing rule body `http:*:443`
- **THEN** parsing returns error containing "invalid domain pattern"

#### Scenario: Deep wildcard rejected
- **WHEN** parsing rule body `http:*.*.example.com:443`
- **THEN** parsing returns error containing "invalid character"

#### Scenario: Non-leftmost wildcard rejected
- **WHEN** parsing rule body `http:sub.*.example.com:443`
- **THEN** parsing returns error containing "wildcard must be single"

#### Scenario: Partial wildcard rejected
- **WHEN** parsing rule body `http:sub*.example.com:443`
- **THEN** parsing returns error containing "wildcard must be single"

#### Scenario: Label starting with hyphen rejected
- **WHEN** parsing rule body `http:-example.com:443`
- **THEN** parsing returns error containing "must not start or end with hyphen"

#### Scenario: Trailing dot rejected
- **WHEN** parsing rule body `http:example.com.:443`
- **THEN** parsing returns error containing "empty label"

#### Scenario: Invalid characters rejected
- **WHEN** parsing rule body `http:exam_ple.com:443`
- **THEN** parsing returns error containing "invalid character"

#### Scenario: Label too long rejected
- **WHEN** parsing rule body `http:<64-char-label>.com:443` (label is 64 characters)
- **THEN** parsing returns error containing "exceeds"

### Requirement: Domain matching

Domain matching SHALL follow the TLS wildcard certificate convention (RFC 9525):
- Exact domain rules match only that exact domain (case-insensitive per RFC 4343)
- Wildcard `*.example.com` matches exactly one subdomain level: `sub.example.com` matches, but `example.com` does NOT match, and `deep.sub.example.com` does NOT match
- Wildcard matching SHALL respect domain boundaries: `*.example.com` does NOT match `notexample.com`

#### Scenario: Exact domain matches
- **GIVEN** rules `net:http:api.example.com:443`
- **WHEN** resolving HTTP request for `api.example.com:443`
- **THEN** request is allowed

#### Scenario: Exact domain case insensitive
- **GIVEN** rules `net:http:API.Example.COM:443`
- **WHEN** resolving HTTP request for `api.example.com:443`
- **THEN** request is allowed

#### Scenario: Wildcard matches one subdomain level
- **GIVEN** rules `net:http:*.example.com:443`
- **WHEN** resolving HTTP request for `api.example.com:443`
- **THEN** request is allowed

#### Scenario: Wildcard does not match apex domain
- **GIVEN** rules `net:http:*.example.com:443`
- **WHEN** resolving HTTP request for `example.com:443`
- **THEN** request is denied (no matching rule)

#### Scenario: Wildcard does not match deep subdomain
- **GIVEN** rules `net:http:*.example.com:443`
- **WHEN** resolving HTTP request for `deep.sub.example.com:443`
- **THEN** request is denied (no matching rule)

#### Scenario: Wildcard respects domain boundary
- **GIVEN** rules `net:http:*.example.com:443`
- **WHEN** resolving HTTP request for `notexample.com:443`
- **THEN** request is denied (no matching rule)

### Requirement: IP and CIDR matching

IP rules SHALL match requests sent to IP addresses only (no DNS resolution). Exact IP rules use an implicit `/32` (IPv4) or `/128` (IPv6) prefix. CIDR rules match any IP within the range. IPv4-mapped IPv6 addresses SHALL be normalized to IPv4 for matching.

#### Scenario: Exact IPv4 matches
- **GIVEN** rules `net:http:192.168.1.50:3000`
- **WHEN** resolving HTTP request for `192.168.1.50:3000`
- **THEN** request is allowed

#### Scenario: CIDR range matches IP within range
- **GIVEN** rules `net:http:10.0.0.0/24:*`
- **WHEN** resolving HTTP request for `10.0.0.5:8080`
- **THEN** request is allowed

#### Scenario: CIDR range does not match IP outside range
- **GIVEN** rules `net:http:10.0.0.0/24:*`
- **WHEN** resolving HTTP request for `10.1.0.5:8080`
- **THEN** request is denied (no matching rule)

#### Scenario: Exact IPv6 matches
- **GIVEN** rules `net:http:[::1]:443`
- **WHEN** resolving HTTP request for `::1:443`
- **THEN** request is allowed

#### Scenario: IPv6 CIDR matches IP within range
- **GIVEN** rules `net:http:[2001:db8::]/32:443`
- **WHEN** resolving HTTP request for `2001:db8::1:443`
- **THEN** request is allowed

#### Scenario: IPv6 CIDR does not match IP outside range
- **GIVEN** rules `net:http:[2001:db8::]/32:443`
- **WHEN** resolving HTTP request for `2001:db9::1:443`
- **THEN** request is denied (no matching rule)

#### Scenario: IP rule does not match domain request
- **GIVEN** rules `net:http:127.0.0.1:80`
- **WHEN** resolving HTTP request for `localhost:80`
- **THEN** request is denied (no matching rule; no DNS resolution)

### Requirement: Port matching

A numeric port in a rule SHALL match only that exact port. A wildcard port `*` SHALL match any port. Port matching is required in addition to target matching — both must match for a rule to apply.

#### Scenario: Exact port matches
- **GIVEN** rules `net:http:example.com:443`
- **WHEN** resolving HTTP request for `example.com:443`
- **THEN** request is allowed

#### Scenario: Exact port does not match different port
- **GIVEN** rules `net:http:example.com:443`
- **WHEN** resolving HTTP request for `example.com:8443`
- **THEN** request is denied (no matching rule)

#### Scenario: Wildcard port matches any port
- **GIVEN** rules `net:http:example.com:*`
- **WHEN** resolving HTTP request for `example.com:8080`
- **THEN** request is allowed

### Requirement: Protocol matching

`http` rules SHALL match any request regardless of transport method (both CONNECT tunnels and plain HTTP). `none` rules SHALL match any request regardless of protocol (protocol-agnostic deny).

#### Scenario: HTTP rule matches plain HTTP request
- **GIVEN** rules `net:http:example.com:80`
- **WHEN** resolving HTTP request for `example.com:80`
- **THEN** request is allowed

#### Scenario: HTTP rule matches CONNECT request
- **GIVEN** rules `net:http:example.com:443`
- **WHEN** resolving HTTP request for `example.com:443`
- **THEN** request is allowed

#### Scenario: None rule denies any request
- **GIVEN** rules `net:none:evil.com:443`
- **WHEN** resolving HTTP request for `evil.com:443`
- **THEN** request is denied (rule: `net:none:evil.com:443`)

### Requirement: Single-dimension target specificity

When multiple rules match a request, the most specific target SHALL win. For domains: exact match beats wildcard. For IPs: longer CIDR prefix beats shorter prefix (longest prefix match). Domain rules and IP rules SHALL never compete — a request targets either a domain or an IP.

No match SHALL result in deny (default-deny).

#### Scenario: Exact domain beats wildcard
- **GIVEN** rules `net:http:*.example.com:443` and `net:none:evil.example.com:443`
- **WHEN** resolving HTTP request for `evil.example.com:443`
- **THEN** request is denied (rule: `net:none:evil.example.com:443`)

#### Scenario: Wildcard allows when no exact deny
- **GIVEN** rules `net:http:*.example.com:443` and `net:none:evil.example.com:443`
- **WHEN** resolving HTTP request for `api.example.com:443`
- **THEN** request is allowed

#### Scenario: Longer CIDR prefix beats shorter
- **GIVEN** rules `net:http:10.0.0.0/24:*` and `net:none:10.0.0.99/32:*`
- **WHEN** resolving HTTP request for `10.0.0.99:8080`
- **THEN** request is denied (rule: `net:none:10.0.0.99/32:*`)

#### Scenario: Shorter CIDR allows when longer does not match
- **GIVEN** rules `net:http:10.0.0.0/24:*` and `net:none:10.0.0.99/32:*`
- **WHEN** resolving HTTP request for `10.0.0.5:8080`
- **THEN** request is allowed

#### Scenario: No match defaults to deny
- **GIVEN** rules `net:http:api.example.com:443`
- **WHEN** resolving HTTP request for `evil.com:443`
- **THEN** request is denied (no matching rule)

### Requirement: No duplicate identity

Two net rules SHALL NOT have the same `(target-pattern, port-pattern)` pair. Target identity is based on canonical form: domains are case-insensitive, CIDRs are normalized to their network base address, exact IPs use implicit single-host CIDR, and IPv4-mapped IPv6 addresses are normalized to IPv4. Duplicate identity SHALL be rejected with an error.

#### Scenario: Same target and port with different actions rejected
- **GIVEN** rules `net:http:example.com:443` and `net:none:example.com:443`
- **WHEN** rules are validated
- **THEN** validation returns error containing "duplicate net rule identity"

#### Scenario: Same CIDR target and port with different actions rejected
- **GIVEN** rules `net:http:10.0.0.0/24:443` and `net:none:10.0.0.0/24:443`
- **WHEN** rules are validated
- **THEN** validation returns error containing "duplicate net rule identity"

#### Scenario: Single-host CIDR duplicates bare IP
- **GIVEN** rules `net:http:127.0.0.1/32:443` and `net:none:127.0.0.1:443`
- **WHEN** rules are validated
- **THEN** validation returns error containing "duplicate net rule identity"

#### Scenario: IPv4-mapped IPv6 duplicates IPv4
- **GIVEN** rules `net:http:[::ffff:127.0.0.1]:443` and `net:none:127.0.0.1:443`
- **WHEN** rules are validated
- **THEN** validation returns error containing "duplicate net rule identity"

#### Scenario: Domain case duplicates
- **GIVEN** rules `net:http:Example.COM:443` and `net:none:example.com:443`
- **WHEN** rules are validated
- **THEN** validation returns error containing "duplicate net rule identity"

#### Scenario: Non-canonical CIDR base duplicates canonical
- **GIVEN** rules `net:http:10.0.0.5/24:8080` and `net:none:10.0.0.0/24:8080`
- **WHEN** rules are validated
- **THEN** validation returns error containing "duplicate net rule identity"

#### Scenario: Same target with different ports allowed
- **GIVEN** rules `net:http:example.com:443` and `net:http:example.com:80`
- **WHEN** rules are validated
- **THEN** validation succeeds

### Requirement: No mixed port patterns

A target pattern SHALL NOT have both wildcard (`*`) and specific port rules. Mixed port patterns SHALL be rejected with an error.

#### Scenario: Wildcard and specific port on same target rejected
- **GIVEN** rules `net:http:example.com:*` and `net:none:example.com:443`
- **WHEN** rules are validated
- **THEN** validation returns error containing "mixed port patterns"

#### Scenario: CIDR with wildcard and specific port rejected
- **GIVEN** rules `net:http:10.0.0.0/24:*` and `net:none:10.0.0.0/24:443`
- **WHEN** rules are validated
- **THEN** validation returns error containing "mixed port patterns"

#### Scenario: Different targets can have different port styles
- **GIVEN** rules `net:http:example.com:*` and `net:http:other.com:443`
- **WHEN** rules are validated
- **THEN** validation succeeds

