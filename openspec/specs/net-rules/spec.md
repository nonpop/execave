# Net Rules Capability

## Purpose

The net-rules capability handles parsing, validation, and resolution of network access control rules. It defines the syntax for network rules, validates target patterns (domains, IPs, CIDRs) and port specifications, enforces single-dimension target specificity for rule resolution, and ensures fail-closed behavior through config-time validation.

## Requirements

### Requirement: Net rule syntax

The system SHALL validate each net rule matches the pattern `net:<action>:<target>:<port>` where:
- `<action>` is one of `https`, `http`, `none`
- `<target>` is a domain pattern, IPv4 address/CIDR, or bracketed IPv6 address/CIDR
- `<port>` is a numeric port (`1`–`65535`) or wildcard `*`

Invalid rules SHALL cause the application to exit with an error before running the command.

#### Scenario: Valid HTTPS domain rule
- **WHEN** config contains rule `net:https:api.example.com:443`
- **THEN** system accepts the rule

#### Scenario: Valid HTTP IP rule
- **WHEN** config contains rule `net:http:192.168.1.50:3000`
- **THEN** system accepts the rule

#### Scenario: Valid CIDR rule
- **WHEN** config contains rule `net:http:10.0.0.0/24:8080`
- **THEN** system accepts the rule

#### Scenario: Valid IPv6 rule
- **WHEN** config contains rule `net:https:[::1]:443`
- **THEN** system accepts the rule

#### Scenario: Valid IPv6 CIDR rule
- **WHEN** config contains rule `net:https:[2001:db8::]/32:443`
- **THEN** system accepts the rule

#### Scenario: Valid wildcard port rule
- **WHEN** config contains rule `net:https:example.com:*`
- **THEN** system accepts the rule

#### Scenario: Invalid action
- **WHEN** config contains rule `net:allow:example.com:443`
- **THEN** system exits with error indicating invalid action

#### Scenario: Missing port field
- **WHEN** config contains rule `net:https:example.com`
- **THEN** system exits with error indicating malformed rule

#### Scenario: Invalid port number
- **WHEN** config contains rule `net:https:example.com:0`
- **THEN** system exits with error indicating invalid port

#### Scenario: Port above range
- **WHEN** config contains rule `net:https:example.com:99999`
- **THEN** system exits with error indicating invalid port

### Requirement: Target parsing order

The target field SHALL be parsed in the following order:
1. If it starts with `[`, parse as bracketed IPv6 — extract address between `[` and `]`, with optional `/N` CIDR suffix after the closing bracket
2. Attempt `net.ParseCIDR(target)` — if it succeeds, classify as CIDR
3. Attempt `net.ParseIP(target)` — if it succeeds, classify as exact IP (implicit `/32` or `/128`)
4. Otherwise, validate as a domain pattern

Invalid targets that fail all parsing steps SHALL cause the application to exit with an error before running the command.

#### Scenario: Bracketed IPv6 parsed as IPv6
- **WHEN** config contains rule `net:https:[::1]:443`
- **THEN** system parses `[::1]` as an exact IPv6 address

#### Scenario: CIDR parsed before IP
- **WHEN** config contains rule `net:http:10.0.0.0/24:8080`
- **THEN** system parses `10.0.0.0/24` as a CIDR range

#### Scenario: Bare IP parsed as exact IP
- **WHEN** config contains rule `net:http:192.168.1.50:3000`
- **THEN** system parses `192.168.1.50` as an exact IPv4 address with implicit `/32`

#### Scenario: Non-IP string parsed as domain
- **WHEN** config contains rule `net:https:api.example.com:443`
- **THEN** system parses `api.example.com` as a domain pattern

#### Scenario: Invalid IP falls through to domain validation and fails
- **WHEN** config contains rule `net:https:123.456.789.0:443`
- **THEN** system exits with error indicating invalid target (fails IP parsing, then fails domain validation because all-numeric labels are rejected)

### Requirement: Domain pattern validation

Domain targets SHALL be validated per RFC 1123. Single-label domains (e.g., `localhost`) are valid. A single wildcard prefix `*.` in the leftmost position is allowed, where `*` replaces exactly one label. Multiple wildcards (e.g., `*.*.example.com`) or wildcards in non-leftmost positions (e.g., `sub.*.example.com`) are invalid. The last label SHALL contain at least one alphabetic character (all-numeric labels are rejected, preventing misclassification of invalid IP addresses as domains). Labels SHALL contain only alphanumeric characters and hyphens, SHALL NOT start or end with a hyphen, and SHALL NOT exceed 63 characters.

#### Scenario: Valid exact domain
- **WHEN** config contains rule `net:https:api.example.com:443`
- **THEN** system accepts the domain

#### Scenario: Valid wildcard domain
- **WHEN** config contains rule `net:https:*.example.com:443`
- **THEN** system accepts the domain

#### Scenario: Valid single-label domain
- **WHEN** config contains rule `net:http:localhost:3000`
- **THEN** system accepts the domain

#### Scenario: All-numeric TLD rejected
- **WHEN** config contains rule `net:https:192.168.1.999:443`
- **THEN** system exits with error (fails IP parsing, then domain validation rejects all-numeric TLD)

#### Scenario: Bare wildcard rejected
- **WHEN** config contains rule `net:https:*:443`
- **THEN** system exits with error indicating invalid domain pattern

#### Scenario: Deep wildcard rejected
- **WHEN** config contains rule `net:https:*.*.example.com:443`
- **THEN** system exits with error indicating invalid domain pattern

#### Scenario: Non-leftmost wildcard rejected
- **WHEN** config contains rule `net:https:sub.*.example.com:443`
- **THEN** system exits with error indicating invalid domain pattern

#### Scenario: Label starting with hyphen rejected
- **WHEN** config contains rule `net:https:-example.com:443`
- **THEN** system exits with error indicating invalid domain

### Requirement: Domain matching

Domain matching SHALL follow the TLS wildcard certificate convention (RFC 9525):
- Exact domain rules match only that exact domain (case-insensitive per RFC 4343)
- Wildcard `*.example.com` matches exactly one subdomain level: `sub.example.com` matches, but `example.com` does NOT match, and `deep.sub.example.com` does NOT match
- Wildcard matching SHALL respect domain boundaries: `*.example.com` does NOT match `notexample.com`

#### Scenario: Exact domain matches
- **WHEN** config contains rule `net:https:api.example.com:443`
- **AND** proxy receives CONNECT request for `api.example.com:443`
- **THEN** rule matches

#### Scenario: Exact domain case insensitive
- **WHEN** config contains rule `net:https:API.Example.com:443`
- **AND** proxy receives CONNECT request for `api.example.com:443`
- **THEN** rule matches

#### Scenario: Wildcard matches one subdomain level
- **WHEN** config contains rule `net:https:*.example.com:443`
- **AND** proxy receives CONNECT request for `api.example.com:443`
- **THEN** rule matches

#### Scenario: Wildcard does not match apex domain
- **WHEN** config contains rule `net:https:*.example.com:443`
- **AND** proxy receives CONNECT request for `example.com:443`
- **THEN** rule does NOT match

#### Scenario: Wildcard does not match deep subdomain
- **WHEN** config contains rule `net:https:*.example.com:443`
- **AND** proxy receives CONNECT request for `deep.sub.example.com:443`
- **THEN** rule does NOT match

#### Scenario: Wildcard respects domain boundary
- **WHEN** config contains rule `net:https:*.example.com:443`
- **AND** proxy receives CONNECT request for `notexample.com:443`
- **THEN** rule does NOT match

### Requirement: IP and CIDR matching

IP rules SHALL match requests sent to IP addresses only (no DNS resolution). Exact IP rules use an implicit `/32` (IPv4) or `/128` (IPv6) prefix. CIDR rules match any IP within the range. IPv4-mapped IPv6 addresses SHALL be normalized to IPv4 for matching.

#### Scenario: Exact IPv4 matches
- **WHEN** config contains rule `net:http:192.168.1.50:3000`
- **AND** proxy receives request for `192.168.1.50:3000`
- **THEN** rule matches

#### Scenario: CIDR range matches IP within range
- **WHEN** config contains rule `net:http:10.0.0.0/24:*`
- **AND** proxy receives request for `10.0.0.5:8080`
- **THEN** rule matches

#### Scenario: CIDR range does not match IP outside range
- **WHEN** config contains rule `net:http:10.0.0.0/24:*`
- **AND** proxy receives request for `10.1.0.5:8080`
- **THEN** rule does NOT match

#### Scenario: Exact IPv6 matches
- **WHEN** config contains rule `net:https:[::1]:443`
- **AND** proxy receives request for `[::1]:443`
- **THEN** rule matches

#### Scenario: IPv6 CIDR matches IP within range
- **WHEN** config contains rule `net:https:[2001:db8::]/32:443`
- **AND** proxy receives request for `[2001:db8::1]:443`
- **THEN** rule matches

#### Scenario: IPv6 CIDR does not match IP outside range
- **WHEN** config contains rule `net:https:[2001:db8::]/32:443`
- **AND** proxy receives request for `[2001:db9::1]:443`
- **THEN** rule does NOT match

#### Scenario: IP rule does not match domain request
- **WHEN** config contains rule `net:http:127.0.0.1:80`
- **AND** proxy receives request for `localhost:80`
- **THEN** rule does NOT match (no DNS resolution; domain and IP rules are independent)

### Requirement: Port matching

A numeric port in a rule SHALL match only that exact port. A wildcard port `*` SHALL match any port. Port matching is required in addition to target matching — both must match for a rule to apply.

#### Scenario: Exact port matches
- **WHEN** config contains rule `net:https:example.com:443`
- **AND** proxy receives CONNECT request for `example.com:443`
- **THEN** rule matches

#### Scenario: Exact port does not match different port
- **WHEN** config contains rule `net:https:example.com:443`
- **AND** proxy receives CONNECT request for `example.com:8443`
- **THEN** rule does NOT match

#### Scenario: Wildcard port matches any port
- **WHEN** config contains rule `net:https:example.com:*`
- **AND** proxy receives CONNECT request for `example.com:8080`
- **THEN** rule matches

### Requirement: Protocol matching

`net:https` rules SHALL match HTTPS (CONNECT) requests only. `net:http` rules SHALL match plain HTTP requests only. `net:none` rules SHALL match any request regardless of protocol (protocol-agnostic deny).

#### Scenario: HTTPS rule matches CONNECT request
- **WHEN** config contains rule `net:https:example.com:443`
- **AND** proxy receives a CONNECT request for `example.com:443`
- **THEN** rule matches

#### Scenario: HTTPS rule does not match plain HTTP request
- **WHEN** config contains rule `net:https:example.com:443`
- **AND** proxy receives a plain HTTP request for `example.com:443`
- **THEN** rule does NOT match

#### Scenario: HTTP rule matches plain HTTP request
- **WHEN** config contains rule `net:http:example.com:80`
- **AND** proxy receives a plain HTTP request for `example.com:80`
- **THEN** rule matches

#### Scenario: HTTP rule does not match CONNECT request
- **WHEN** config contains rule `net:http:example.com:80`
- **AND** proxy receives a CONNECT request for `example.com:80`
- **THEN** rule does NOT match

#### Scenario: None rule matches any protocol
- **WHEN** config contains rule `net:none:evil.com:443`
- **AND** proxy receives a CONNECT request for `evil.com:443`
- **THEN** rule matches (deny)

### Requirement: Single-dimension target specificity

When multiple rules match a request, the most specific target SHALL win. For domains: exact match beats wildcard. For IPs: longer CIDR prefix beats shorter prefix (longest prefix match). Domain rules and IP rules SHALL never compete — a request targets either a domain or an IP.

No match SHALL result in deny (default-deny).

#### Scenario: Exact domain beats wildcard
- **WHEN** config contains `net:https:*.example.com:443` and `net:none:evil.example.com:443`
- **AND** proxy receives CONNECT request for `evil.example.com:443`
- **THEN** deny (exact `evil.example.com` beats wildcard `*.example.com`)

#### Scenario: Wildcard allows when no exact deny
- **WHEN** config contains `net:https:*.example.com:443` and `net:none:evil.example.com:443`
- **AND** proxy receives CONNECT request for `api.example.com:443`
- **THEN** allow (wildcard matches, exact deny does not apply)

#### Scenario: Longer CIDR prefix beats shorter
- **WHEN** config contains `net:http:10.0.0.0/24:*` and `net:none:10.0.0.99/32:*`
- **AND** proxy receives request for `10.0.0.99:8080`
- **THEN** deny (`/32` beats `/24`)

#### Scenario: Shorter CIDR allows when longer does not match
- **WHEN** config contains `net:http:10.0.0.0/24:*` and `net:none:10.0.0.99/32:*`
- **AND** proxy receives request for `10.0.0.5:8080`
- **THEN** allow (`/24` matches, `/32` does not)

#### Scenario: No match defaults to deny
- **WHEN** config contains `net:https:api.example.com:443`
- **AND** proxy receives CONNECT request for `evil.com:443`
- **THEN** deny (no matching rule)

### Requirement: No duplicate identity

Two net rules SHALL NOT have the same `(target-pattern, port-pattern)` pair. Duplicate identity SHALL cause the application to exit with an error before running the command.

#### Scenario: Same target and port with different actions rejected
- **WHEN** config contains `net:https:example.com:443` and `net:none:example.com:443`
- **THEN** system exits with error indicating duplicate net rule identity

#### Scenario: Same CIDR target and port with different actions rejected
- **WHEN** config contains `net:https:10.0.0.0/24:443` and `net:none:10.0.0.0/24:443`
- **THEN** system exits with error indicating duplicate net rule identity

#### Scenario: Same target with different ports allowed
- **WHEN** config contains `net:https:example.com:443` and `net:http:example.com:80`
- **THEN** system accepts the config

### Requirement: No mixed port patterns

A target pattern SHALL NOT have both wildcard (`*`) and specific port rules. Mixed port patterns SHALL cause the application to exit with an error before running the command.

#### Scenario: Wildcard and specific port on same target rejected
- **WHEN** config contains `net:https:example.com:*` and `net:none:example.com:443`
- **THEN** system exits with error indicating mixed port patterns

#### Scenario: CIDR with wildcard and specific port rejected
- **WHEN** config contains `net:https:10.0.0.0/24:*` and `net:none:10.0.0.0/24:443`
- **THEN** system exits with error indicating mixed port patterns

#### Scenario: Different targets can have different port styles
- **WHEN** config contains `net:https:example.com:*` and `net:https:other.com:443`
- **THEN** system accepts the config
