## Context

The proxy handles CONNECT requests (HTTPS tunneling) and plain HTTP requests. Currently, `net:https` and `net:http` are distinct protocols — an `https` rule only matches CONNECT requests, and an `http` rule only matches plain HTTP requests.

The proxy is a non-MITM TCP relay: after authorizing a CONNECT request, it blindly forwards bytes between client and server (`io.Copy` in both directions). It cannot verify that TLS actually occurs. If the adversary controls a remote server, they can exchange plaintext through a `net:https` rule. This makes the `https` label misleading — it implies a security guarantee the system cannot enforce.

## Goals / Non-Goals

**Goals:**
- Remove `https` as a net rule action. Only `http` and `none` remain.
- `http` rules match both CONNECT (tunneled) and plain HTTP requests.
- Remove `HTTPS` as a distinct access log operation type. Both request types log as `HTTP`.
- Document the inherent HTTPS enforcement limitation.

**Non-Goals:**
- MITM proxy with TLS termination/re-encryption (would require CA injection, breaks certificate pinning, fundamentally changes the security model).
- Partial TLS verification (peeking at first bytes, handshake checking) — trivially bypassable when both endpoints conspire.

## Decisions

### 1. Merge protocols into single `http`

Remove `ProtocolHTTPS`. The `ProtocolHTTP` constant now matches both CONNECT and plain HTTP requests.

`protocolCompatible()` still works: `protocolNone` matches any protocol, `ProtocolHTTP` matches `ProtocolHTTP`. Since the proxy now passes `ProtocolHTTP` for both request types, all `http` rules match both.

**Why not remove the protocol dimension entirely?** The `protocol` field still serves a purpose: `protocolNone` means "deny" vs `ProtocolHTTP` means "allow" (line 69 of resolver.go: `allowed := bestRule.protocol != protocolNone`). The compatibility check becomes trivially true for `http` rules, but the deny/allow distinction remains.

### 2. Merge operation types into single `HTTP`

Remove `OperationHTTPS`. Both CONNECT and plain HTTP requests log as `OperationHTTP`.

**Rationale:** The user trusts the proxy. The CONNECT/plain distinction provided no actionable information since the user cannot verify TLS anyway.

**Impact on deduplication:** The access log deduplicates on `(operation, target, result)`. Merging means a CONNECT request and a plain HTTP request to the same `host:port` with the same result will deduplicate. This is acceptable — the same `host:port` with the same result should appear once regardless of transport method.

### 3. Breaking config change with generic error

Existing configs with `net:https:` rules will fail to parse with `invalid action "https" (must be 'http' or 'none')`. No special migration message — the valid actions are listed in the error.

## Risks / Trade-offs

- **Breaking change**: Existing configs with `net:https:` rules must be updated. The error message lists valid actions, making migration straightforward.
- **Loss of transport visibility**: Access log no longer distinguishes CONNECT from plain HTTP. Accepted because the distinction is not actionable.
- **Protocol dimension becomes trivial**: `protocolCompatible()` always returns true for `http` rules. Code remains structurally sound; the `none` deny mechanism still works correctly.
