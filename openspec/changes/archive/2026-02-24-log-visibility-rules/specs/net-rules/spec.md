## ADDED Requirements

### Requirement: Log rule syntax

`ParseLogRule` SHALL validate each rule body matches the pattern `<visibility>:<target>:<port>` where:
- `<visibility>` is one of `log`, `nolog`
- `<target>` is a domain pattern, IPv4 address/CIDR, or bracketed IPv6 address/CIDR (same parsing as access rules)
- `<port>` is a numeric port (`1`–`65535`) or wildcard `*`

Invalid rules SHALL be rejected with an error.

#### Scenario: Valid nolog domain rule

- **WHEN** parsing log rule body `nolog:telemetry.example.com:443`
- **THEN** parsing succeeds with Visible=false

#### Scenario: Valid log domain rule

- **WHEN** parsing log rule body `log:api.example.com:443`
- **THEN** parsing succeeds with Visible=true

#### Scenario: Valid nolog wildcard domain rule

- **WHEN** parsing log rule body `nolog:*.example.com:*`
- **THEN** parsing succeeds

#### Scenario: Valid nolog CIDR rule

- **WHEN** parsing log rule body `nolog:10.0.0.0/24:*`
- **THEN** parsing succeeds

#### Scenario: Valid nolog IPv6 rule

- **WHEN** parsing log rule body `nolog:[::1]:443`
- **THEN** parsing succeeds

#### Scenario: Invalid visibility

- **WHEN** parsing log rule body `hide:example.com:443`
- **THEN** parsing returns error containing "invalid visibility type"

#### Scenario: Missing port field

- **WHEN** parsing log rule body `nolog:example.com`
- **THEN** parsing returns error containing "malformed rule"

#### Scenario: Invalid port number

- **WHEN** parsing log rule body `nolog:example.com:0`
- **THEN** parsing returns error containing "invalid port"

### Requirement: Log rule validation

`ValidateLogRules` SHALL reject log rule sets where two rules have the same `(target-pattern, port-pattern)` identity pair. Identity is determined using the same canonical form as access rules: domains are case-insensitive, CIDRs are normalized to their network base address, exact IPs use implicit single-host CIDR, and IPv4-mapped IPv6 addresses are normalized to IPv4.

`ValidateLogRules` SHALL also reject log rule sets where a target has both wildcard (`*`) and specific port rules.

#### Scenario: Duplicate log rule identity rejected

- **WHEN** log rules `nolog:example.com:443` and `log:example.com:443` are validated
- **THEN** validation returns error containing "duplicate net log rule identity"

#### Scenario: Domain case duplicates rejected

- **WHEN** log rules `nolog:Example.COM:443` and `log:example.com:443` are validated
- **THEN** validation returns error containing "duplicate net log rule identity"

#### Scenario: Mixed port patterns rejected

- **WHEN** log rules `nolog:example.com:*` and `log:example.com:443` are validated
- **THEN** validation returns error containing "mixed port patterns"

#### Scenario: Same identity in access and log rules allowed

- **WHEN** access rules contain `https:example.com:443` and log rules contain `nolog:example.com:443`
- **THEN** validation succeeds (access and log are different namespaces)

### Requirement: Log rule resolution

`LogResolver.Visible` SHALL determine whether an entry for a given host and port should be displayed. It SHALL use the same single-dimension target specificity resolution as access rules: for domains, exact match beats wildcard; for IPs, longer CIDR prefix beats shorter. If the most specific matching rule has visibility `nolog`, the entry is not visible. If `log`, the entry is visible. If no log rule matches, the entry is visible (default: show).

Log rule resolution is protocol-agnostic — it matches on target and port only, regardless of whether the original request was HTTP or HTTPS.

#### Scenario: Nolog hides matching host

- **WHEN** a LogResolver is created with rule `nolog:telemetry.example.com:443`
- **AND** `Visible` is called with host `"telemetry.example.com"` and port `443`
- **THEN** the result is false

#### Scenario: Log overrides wildcard nolog

- **WHEN** a LogResolver is created with rules `nolog:*.example.com:443` and `log:api.example.com:443`
- **AND** `Visible` is called with host `"api.example.com"` and port `443`
- **THEN** the result is true

#### Scenario: Wildcard nolog hides matching subdomain

- **WHEN** a LogResolver is created with rules `nolog:*.example.com:443` and `log:api.example.com:443`
- **AND** `Visible` is called with host `"cdn.example.com"` and port `443`
- **THEN** the result is false

#### Scenario: No matching log rule defaults to visible

- **WHEN** a LogResolver is created with rule `nolog:*.example.com:443`
- **AND** `Visible` is called with host `"other.com"` and port `443`
- **THEN** the result is true

#### Scenario: Port-specific nolog

- **WHEN** a LogResolver is created with rule `nolog:example.com:443`
- **AND** `Visible` is called with host `"example.com"` and port `8080`
- **THEN** the result is true (port doesn't match)

#### Scenario: Wildcard port nolog

- **WHEN** a LogResolver is created with rule `nolog:example.com:*`
- **AND** `Visible` is called with host `"example.com"` and port `8080`
- **THEN** the result is false

#### Scenario: Longer CIDR prefix beats shorter

- **WHEN** a LogResolver is created with rules `nolog:10.0.0.0/8:*` and `log:10.0.0.0/24:*`
- **AND** `Visible` is called with host `"10.0.0.5"` and port `8080`
- **THEN** the result is true (the /24 log rule is more specific than the /8 nolog rule)
