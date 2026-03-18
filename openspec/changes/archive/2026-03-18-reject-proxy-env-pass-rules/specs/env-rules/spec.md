## ADDED Requirements

### Requirement: Proxy-managed variable names are rejected at parse time

The system SHALL reject env rules targeting any of the six proxy-managed variable names: `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`, `no_proxy`. These variables are always set or stripped by the tunnel; passing them from the host has no effect and indicates misconfiguration. The error SHALL identify the variable name and state it is managed by the tunnel.

#### Scenario: Uppercase HTTP_PROXY rejected

- **WHEN** parsing rule body `pass:HTTP_PROXY`
- **THEN** parsing returns error containing "managed by the tunnel"

#### Scenario: Uppercase HTTPS_PROXY rejected

- **WHEN** parsing rule body `pass:HTTPS_PROXY`
- **THEN** parsing returns error containing "managed by the tunnel"

#### Scenario: Uppercase NO_PROXY rejected

- **WHEN** parsing rule body `pass:NO_PROXY`
- **THEN** parsing returns error containing "managed by the tunnel"

#### Scenario: Lowercase http_proxy rejected

- **WHEN** parsing rule body `pass:http_proxy`
- **THEN** parsing returns error containing "managed by the tunnel"

#### Scenario: Lowercase https_proxy rejected

- **WHEN** parsing rule body `pass:https_proxy`
- **THEN** parsing returns error containing "managed by the tunnel"

#### Scenario: Lowercase no_proxy rejected

- **WHEN** parsing rule body `pass:no_proxy`
- **THEN** parsing returns error containing "managed by the tunnel"

#### Scenario: Non-proxy variable names not affected

- **WHEN** parsing rule body `pass:HOME`
- **THEN** parsing succeeds with Name `HOME`
