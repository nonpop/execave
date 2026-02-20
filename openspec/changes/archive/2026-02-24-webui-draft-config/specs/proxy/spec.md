# Proxy Capability — Delta

## ADDED Requirements

### Requirement: Runtime resolver replacement

`proxy.SetResolver` SHALL atomically replace the net rules resolver used by the proxy for all subsequent requests. In-flight requests that have already loaded the previous resolver SHALL complete with the old rules; new requests SHALL use the new resolver. `SetResolver` SHALL be safe for concurrent use with request handlers.

#### Scenario: SetResolver updates rules for new requests

- **WHEN** the proxy is started with a resolver that denies `evil.example.com:443`
- **AND** SetResolver is called with a new resolver that allows `evil.example.com:443`
- **AND** a CONNECT request for `evil.example.com:443` is received after SetResolver returns
- **THEN** the request is allowed (tunneled)

#### Scenario: SetResolver from deny-all to allow

- **WHEN** the proxy is started with an empty resolver (deny-all)
- **AND** SetResolver is called with a resolver containing `net:https:api.example.com:443`
- **AND** a CONNECT request for `api.example.com:443` is received after SetResolver returns
- **THEN** the request is allowed

#### Scenario: SetResolver from allow to deny-all

- **WHEN** the proxy is started with a resolver allowing `api.example.com:443`
- **AND** SetResolver is called with an empty resolver (deny-all)
- **AND** a CONNECT request for `api.example.com:443` is received after SetResolver returns
- **THEN** the request is denied with 403
