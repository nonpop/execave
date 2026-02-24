## Why

`net:https` rules imply TLS verification, but the proxy is a non-MITM TCP relay — it cannot verify that TLS actually occurs on CONNECT tunnels. If the adversary controls a remote server, they can exchange plaintext through a `net:https` rule. This is unfixable without MITM (which is out of scope), making the `https` protocol label misleading. It should be removed.

## What Changes

- **BREAKING**: Remove `https` as a valid net rule action. Only `http` and `none` remain.
- `http` rules now match both plain HTTP requests and CONNECT tunnels (previously only matched plain HTTP).
- Remove `HTTPS` as a distinct access log operation type. Both plain HTTP and CONNECT requests log as `HTTP`.
- Document the limitation: HTTPS enforcement is not possible without a MITM proxy.

## Playbooks

### New Playbooks

None.

### Modified Playbooks

- `restricting-network`: Use cases change — `net:https` examples become `net:http`, HTTPS-specific use cases removed.
- `configuring-execave`: Config examples change — `net:https` rules become `net:http`.
- `monitoring-access`: Access log examples change — HTTPS operation type replaced by HTTP.
- `preventing-sandbox-escape`: Network-related escape prevention examples use `net:http` instead of `net:https`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `net-rules`: Remove `https` protocol. `http` matches both plain HTTP and CONNECT requests.
- `proxy`: CONNECT handler resolves against `ProtocolHTTP`. Remove `OperationHTTPS` from logging.
- `access-log`: Remove `HTTPS` operation type.
- `config`: `net:https` is no longer a valid rule format.
- `web-ui`: Log filtering no longer needs to handle `HTTPS` as a distinct operation type.

## Impact

- **Config format**: Breaking change — existing configs with `net:https:` rules will fail to parse.
- **Security model**: Documents an inherent limitation. No new security risk — the limitation already existed, it was just undocumented and the config syntax was misleading.
- **Trust boundaries**: No change. Proxy still enforces default-deny allowlist. The change removes a false guarantee rather than adding or modifying enforcement.
- **Code**: `internal/netrules`, `internal/proxy`, `internal/accesslog`, `internal/webui`, `internal/config` packages affected.
- **Documentation**: `security-model.md`, `architecture.md`, `README.md` need updates.
