## Context

Execave sandboxes AI coding agents using bubblewrap (`bwrap`) with filesystem isolation via bind mounts and access rules (see `docs/security-model.md`). Network access is currently shared unconditionally (`--share-net`), allowing sandboxed processes to reach any host. This is the primary threat model gap — a compromised or malicious agent can exfiltrate data to arbitrary destinations. The "Network access is allowed (no network isolation)" limitation in `docs/security-model.md` is what this change removes.

Constraints:
- Zero external runtime dependencies (pure Go stdlib)
- Linux-only, requires bubblewrap
- Security-critical: fail-closed, simple, auditable
- Breaking change acceptable (network isolated by default)

## Goals / Non-Goals

**Goals:**
- Isolate sandboxed processes from the network by default (no `--share-net`)
- Allow configurable access to specific domains, IPs, and CIDR ranges via `net:` rules
- Enforce network policy through absence of connectivity (no NIC, no route) rather than filtering
- Extend access logging so both FS and network events share a single log sink

**Non-Goals:**
- Non-HTTP protocol support (SSH, raw TCP) — HTTP/HTTPS covers the AI agent use case
- HTTPS content inspection (path-level filtering) — would require MITM, breaks trust model
- Bandwidth limiting or rate limiting
- Per-process network policy (all processes in the sandbox share the same rules)
- Transparent proxy (SNI-based interception without HTTP_PROXY) — simpler UDS approach preferred

## Decisions

### 1. UDS-based forward proxy over slirp4netns

**Decision:** Use a Unix domain socket (UDS) as the sole network exit path from the sandbox. A forward proxy on the host listens on the UDS; a tunnel inside the sandbox bridges loopback TCP to the UDS and sets `HTTP_PROXY`/`HTTPS_PROXY`.

**Kernel guarantee:** bwrap's `--unshare-all` without `--share-net` creates a new network namespace with only an isolated loopback interface — no NIC, no route to the host or internet. This is enforced by the Linux kernel's network namespace isolation (`CLONE_NEWNET`). The sandbox cannot create a bridge to the host because `CAP_NET_ADMIN` is scoped to the sandbox's own namespace. The UDS is a filesystem object — bwrap bind-mounts it into the sandbox, making it the only path to the host network.

**What if the proxy fails?** Proxy crash makes the UDS endpoint unavailable. New connections from the sandbox get `ECONNREFUSED` on the UDS — fail-closed. In-flight connections drop. No fallback path exists because there is no NIC.

**Why not slirp4netns + iptables:** slirp4netns provides a virtual NIC via a TAP device, giving the sandbox a real network stack. This requires iptables/nftables to restrict traffic — enforcement depends on *filtering present traffic* rather than *absence of connectivity*. What if a firewall rule is wrong? Full network access leaks. DNS inside the sandbox must be controlled separately. UDP/ICMP channels exist unless explicitly blocked. Domain-level filtering requires resolving domains to IPs ahead of time (fragile with CDNs/dynamic IPs).

**Why not slirp4netns + transparent proxy:** Intercepts all traffic via nftables REDIRECT, reads SNI from TLS ClientHello. Handles proxy-unaware applications but adds significant complexity (slirp4netns lifecycle, nftables setup/teardown, DNS resolver control). What if the interception layer has a bug? Traffic bypasses the proxy entirely because a real NIC exists — fail-open.

**Auditability:** The UDS approach is auditable by inspection: check that `--share-net` is absent (kernel isolates network), check that only one UDS is bind-mounted (single exit path), check that the proxy listens only on that UDS. No firewall rules to audit, no TAP device configuration, no DNS resolver setup.

**Trade-off:** Applications that ignore `HTTP_PROXY` (e.g., agent-written code using raw sockets) silently fail to connect rather than being transparently proxied. For AI coding agents making HTTPS calls to well-known APIs, this is acceptable — `HTTP_PROXY` support is near-universal in HTTP clients and build tools.

### 2. Network isolated by default (breaking change)

**Decision:** Remove `--share-net` unconditionally from `sandbox.go`. Configs without `net:` rules get no network access.

**Bwrap change:** Currently sandbox.go passes `--unshare-all`, `--share-net`. After this change: just `--unshare-all`. The `--share-net` flag re-shares the host's network namespace — removing it means bwrap creates an isolated network namespace (kernel `CLONE_NEWNET`). This matches the existing default-deny model for filesystem access (see `docs/security-model.md` "Default-Deny Model").

**What if `--share-net` removal is missed in a code path?** The sandbox would retain full network access. Mitigated by removing `--share-net` unconditionally in one place (the base args in `BuildBwrapArgs`), not conditionally. There is no code path that should re-add it.

**Rationale:** Fail-closed is the correct default for a security sandbox. Shared network was always a documented limitation, not a feature. The migration path is explicit: add `net:` rules for needed services.

**Alternative considered:** Opt-in isolation (add a flag to enable network filtering). Rejected because it inverts the security model — users who forget to opt in remain vulnerable.

### 3. Extend access log with network operations

**Decision:** Add `HTTPS` and `HTTP` operation types to `internal/accesslog/` alongside existing `READ`/`WRITE`. Both `monitor` (FS entries) and `proxy` (network entries) feed entries to the shared `accesslog.Logger`.

**Entry format:** Network entries use the same columnar format as FS entries: `HTTPS api.github.com:443 OK net:https:api.github.com:443`.

**Deduplication semantics:** The dedup key is `(operation, target, result)`. The same target with different results produces separate entries.

**Rationale:** The `accesslog` package owns the log file, entry format, deduplication, and infrastructure path filtering. Extending it with network operation types is a natural fit — the proxy feeds entries the same way monitor does.

### 4. Net rule format: `net:<action>:<target>:<port>`

**Decision:** Four-field colon-separated format where the first field doubles as protocol and action (`https` = allow HTTPS, `http` = allow HTTP, `none` = deny).

**Rationale:** Mirrors FS rule format (`fs:<permission>:<path>`) where the second field is both the permission level and the action. Keeps the rule language consistent.

**Target parsing order:** Bracketed IPv6 → CIDR → IP → domain. No heuristics — invalid IPs fall through to domain validation. Single-label domains like `localhost` are valid. RFC 1123 allows labels to start with digits but requires the last label to contain at least one alphabetic character, so all-numeric strings like `123.456.789.0` are rejected by domain validation at config load time (fail-closed).

**Domain pattern restrictions:** A wildcard prefix `*.` is allowed, where `*` replaces exactly one label. Only a single wildcard in the leftmost position is permitted — patterns like `*.*.example.com` or `sub.*.example.com` are invalid and rejected at config load time. This follows RFC 9525 (TLS service identity standard), which explicitly requires wildcards to be single and leftmost-only, and keeps the implementation simple and auditable.

**What if a target is misclassified?** A rule intended for an IP could be matched as a domain (or vice versa), causing the wrong matching logic to apply and potentially allowing or denying unintended requests. Mitigation: the parsing order is deterministic and unambiguous (brackets force IPv6, `net.ParseCIDR` succeeds or fails, `net.ParseIP` succeeds or fails, everything else is validated as a domain per RFC 1123). Invalid inputs like typo'd IP `123.456.789.0` fail IP parsing, then fail domain validation (all-numeric last label) — the config is rejected at load time (fail-closed).

**IPv6 bracket convention:** IPv6 addresses use `[addr]` brackets following RFC 3986, with optional CIDR suffix after the bracket: `[2001:db8::]/32`. This prevents ambiguity between IPv6 colons and the rule field separator.

### 5. Single-dimension target specificity for resolution

**Decision:** Most specific target wins. For domains: exact match beats wildcard. For IPs: longer CIDR prefix wins (longest prefix match, same as routing tables). Domain rules and IP rules never compete — a request targets either a domain or an IP.

**Why domain specificity is trivial:** Since wildcards are restricted to a single `*` in the leftmost position, a pattern can only match a host with the same number of labels (e.g., `*.example.com` matches `foo.example.com` but not `example.com` or `deep.sub.example.com`). Two patterns that match the same host must share the same non-wildcard suffix — so the only conflict is an exact domain vs. a wildcard with the same suffix, and exact always wins.

**Rationale:** Analogous to FS rules using single-dimension path-length specificity (longest prefix match in `fsrules.Resolver`). No port tiebreaker needed because config validation prevents ambiguity (no duplicate identity, no mixed port patterns on the same target).

**What if specificity resolution is wrong?** A more permissive rule could win over a more restrictive one. For example, if `net:https:*.github.com:443` (allow) incorrectly beats `net:none:evil.github.com:443` (deny), the sandbox can reach `evil.github.com`. Mitigated by keeping specificity single-dimensional (only target, no port tiebreaker), which is simple to implement and audit. Fuzz testing covers resolution correctness.

**Edge cases for domain matching:**
- `*.github.com` does NOT match `github.com` itself (wildcard requires exactly one subdomain label)
- `*.github.com` does NOT match `deep.sub.github.com` (only one level)
- `*.github.com` does NOT match `notgithub.com` (`.` boundary prevents suffix matching)
- `*.*.github.com` is INVALID (only single wildcard allowed)
- `sub.*.github.com` is INVALID (wildcard must be leftmost)
- Domain comparison is case-insensitive (per RFC 4343)

**Edge cases for IP/CIDR matching:**
- `10.0.0.0/24` and `10.0.0.5/32` can coexist — `/32` wins for `10.0.0.5`, `/24` wins for other IPs in range
- IP rules only match requests sent to IP addresses, never to domains (no DNS resolution by the proxy for matching purposes)

### 6. Config validation: two rules

**Decision:**
1. No duplicate `(target-pattern, port-pattern)` pairs
2. A target pattern cannot have both wildcard (`*`) and specific port rules

**Rationale:** These two rules guarantee that at most one rule can match at any given target specificity level, making resolution unambiguous without port tiebreakers. Analogous to FS rules rejecting duplicate paths (`fsrules.Validate`).

**What if validation is bypassed or incomplete?** Two rules at the same specificity level could match the same request with conflicting actions, and the result would depend on rule ordering (nondeterministic). This means whether a request is allowed or denied becomes unpredictable and could vary between executions if rules are reordered. Mitigation: validation runs at config load time and rejects the config if it fails (fail-closed), so the command never runs with an ambiguous config.

**Trade-off:** Cannot express "allow all ports except port X" for a single target. Acceptable for the AI agent use case (typically allowlisting specific ports). Relaxing this later is a backwards-compatible change.

### 7. Domain matching follows TLS wildcard convention (RFC 9525)

**Decision:** `*.github.com` matches exactly one subdomain level (`api.github.com` yes, `github.com` no, `deep.sub.github.com` no). Only a single wildcard in the leftmost position is permitted — patterns like `*.*.github.com` or `sub.*.github.com` are invalid and rejected at config load time.

**Rationale:** Follows RFC 9525 (TLS service identity standard), which explicitly requires "There is only one wildcard character" and wildcards must be "only as the complete content of the left-most label." This convention is used by browsers, Kubernetes Ingress, and nginx. Single wildcard restriction keeps parsing and matching logic simple and auditable (critical for security code), and multi-level wildcards provide no practical benefit for the AI agent use case. This differs from FS rule matching where `fs:ro:/foo` includes all descendants — justified because domains and filesystem paths have different natural granularity.

### 8. Proxy as a custom Go implementation

**Decision:** Purpose-built HTTP forward proxy in `internal/proxy/`. Handles CONNECT (HTTPS tunneling) and plain HTTP forwarding. Listens on UDS.

**Why not 3rd party proxies (Squid, Privoxy, Tinyproxy):** Additional system dependencies (C/C++ programs) to install/manage. Feature bloat: Squid (~50MB) has enterprise features, Privoxy has content filtering, Tinyproxy is general-purpose. A purpose-built Go proxy is smaller, auditable, and has only what's needed for domain allowlisting.

**Transparent handling of connection types:** For CONNECT requests, the proxy sees only the domain:port from the CONNECT line. The actual request/response content is encrypted end-to-end. WebSocket upgrades happen inside the encrypted tunnel transparently. SSE is a long-lived HTTP response — no special handling needed.

**What if the proxy has a bug that allows non-allowlisted traffic?** The proxy is the sole enforcement point for network policy (after the kernel namespace provides the hard boundary). A bug here could allow access to non-allowlisted domains. Mitigated by: (1) the proxy is small and purpose-built — no unnecessary features to introduce bugs, (2) the allowlist check is a single function (`Allowlist.Check`) that returns allow/deny, easy to audit and fuzz test, (3) default is deny — the check must explicitly return allow.

**Implementation details:**
- CONNECT handler: validates domain:port from request line, checks allowlist, if allowed dials the target on the host, responds `200 Connection Established`, then bidirectional relay (two goroutines copying `io.Copy`). Connection closes when either side closes.
- HTTP handler: validates Host header, checks allowlist, if allowed forwards request using `http.Transport` (strips hop-by-hop headers), copies response back.
- Malformed requests: proxy rejects with appropriate HTTP error. A sandboxed process that opens the UDS directly and sends raw bytes gets a malformed-request error — no bypass.
- Concurrency: each connection handled in its own goroutine. The allowlist is read-only after construction — no locks needed.

### 9. Tunnel as an internal subcommand

**Decision:** `execave network-tunnel` is a visible cobra subcommand. The tunnel binary is the execave binary itself, bind-mounted read-only into the sandbox.

**Rationale:** No separate binary to build/distribute. The execave binary is already available and can be bind-mounted. The subcommand listens on `127.0.0.1:0` (ephemeral port), bridges TCP to UDS, sets `HTTP_PROXY`/`HTTPS_PROXY` (and lowercase variants), unsets `NO_PROXY`/`no_proxy`, and execs the user command.

**Bwrap bind-mount:** The execave binary is bind-mounted read-only into the sandbox (e.g., `--ro-bind /path/to/execave /tmp/execave`). A sandboxed process cannot overwrite it (read-only mount, kernel-enforced). Even if the process replaces the tunnel with its own binary, all traffic still routes through the UDS to the proxy allowlist — no bypass.

**What if the tunnel fails to start?** The user command never runs (tunnel is the wrapper). No network access is possible because there's no listener bridging TCP to UDS. Fail-closed.

**What if the agent sets `NO_PROXY=*` or `no_proxy=*`?** The agent's HTTP client would attempt to bypass the proxy and connect directly. However, direct connections fail because there's no NIC — these variables only affect which requests skip the proxy, and without a NIC the direct path doesn't exist. Mitigation: the tunnel unsets both uppercase and lowercase variants (`NO_PROXY`, `no_proxy`) before running the user command to prevent initial bypasses, but even if the agent re-sets them, the lack of a network interface prevents the bypass.

**Implementation details:**
- Listens on `127.0.0.1:0` — the sandbox's isolated loopback. The port is ephemeral (OS-assigned), written to `HTTP_PROXY`/`HTTPS_PROXY` and `http_proxy`/`https_proxy` env vars.
- For each TCP connection: dials the UDS, bidirectional relay (two goroutines with `io.Copy`).
- Runs user command as subprocess via `os/exec`. Propagates exit code. If subprocess exits, tunnel waits for in-flight connections to drain, then exits.
- The tunnel does NOT perform any filtering — all policy enforcement is in the proxy on the host side.

**Lifecycle:** bwrap → tunnel (starts listener, sets env) → user command (subprocess). User command exits → tunnel exits → bwrap exits.

## Sandbox Boundary Changes

Changes to `sandbox.go`'s `BuildBwrapArgs`, mapped to bwrap/kernel guarantees:

| Change | bwrap args | Kernel guarantee |
|--------|-----------|-----------------|
| Remove `--share-net` | `--unshare-all` (no `--share-net`) | `CLONE_NEWNET`: isolated network namespace, no NIC, no route |
| Bind-mount UDS | `--ro-bind <host-uds> /tmp/execave-proxy.sock` | UDS is a filesystem object; read-only mount prevents deletion |
| Bind-mount execave binary | `--ro-bind <execave-path> /tmp/execave` | Read-only mount prevents tampering |
| Wrap command with tunnel | `-- /tmp/execave network-tunnel <uds-path> -- <original-command>` | Tunnel is first process; sets up proxy env before user command |

When no net rules are present: only the `--share-net` removal applies. No UDS, no tunnel, no bind-mounts — the sandbox simply has no network at all.

**New additions to the security model** (extends `docs/security-model.md` Guarantees table):

| Guarantee | Mechanism |
|-----------|-----------|
| No network access without net rules | Network namespace isolation (no `--share-net`) |
| Network access only through allowlisted proxy | UDS is sole exit path; proxy enforces allowlist |
| No DNS exfiltration | No DNS resolver in sandbox; proxy resolves on host |
| No UDP/ICMP covert channels | No network stack in sandbox |
| Tunnel binary tamper-proof | Read-only bind mount |

**New additions to the Attacks & Mitigations table:**

| Attack | Mitigation | Residual Risk |
|--------|-----------|---------------|
| Ignore HTTP_PROXY, connect directly | No NIC, no route — connection fails | None |
| DNS exfiltration | No DNS in sandbox | None |
| UDP/ICMP covert channel | No network stack | None |
| Send raw bytes to UDS | Proxy rejects malformed HTTP | None |
| Create new NIC in namespace | CAP_NET_ADMIN scoped to sandbox namespace; can't bridge to host | None |
| Kill tunnel, start own process | Still goes through UDS → proxy → allowlist | None |
| Domain fronting via CDN | N/A | Shared CDN IPs (document: use specific domains) |
| Connect by IP to bypass domain rules | Direct IP connections fail (no route); via proxy, IP targets matched against IP rules only | None |

## Risks / Trade-offs

**[Proxy-unaware applications fail silently]** Applications that ignore `HTTP_PROXY` and attempt direct connections will fail (no NIC, no route). This is by design — fail-closed is preferable to fail-open. Mitigation: document clearly; HTTP_PROXY support is near-universal for HTTP clients.

**[Domain fronting via CDN]** If an allowed domain shares a CDN with a malicious service, the agent could reach the malicious service via the shared IP. Mitigation: document that users should allow specific domains, not broad CDN wildcards.

**[Data tunneling over allowed domains]** If the agent controls the server at an allowed domain, it can exfiltrate through it. Inherent limitation of domain-level filtering — no mitigation beyond restricting the allowlist.

**[Loopback semantics confusion]** `net:http:127.0.0.1:3000` allows the agent to reach a service on the *host's* loopback, even though `127.0.0.1` inside the sandbox refers to the sandbox's isolated loopback. Useful for local dev servers but must be documented clearly.

**[Monitor setup phase detection]** Monitor currently counts 2 execve calls to detect when bwrap setup is complete. With the tunnel wrapper, this becomes 3 execve calls. Must be parameterized based on whether net rules are present.
