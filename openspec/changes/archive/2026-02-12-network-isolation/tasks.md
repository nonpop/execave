## 1. Net rules — parsing, validation, and resolution

- [x] 1.1 Create `internal/netrules/` package with `Rule` type, `Protocol` enum (`HTTPS`, `HTTP`, `None`), and `Target` type (domain, IPv4, IPv6, CIDR variants)
- [x] 1.2 Implement `Parse()` function with target parsing order: bracketed IPv6 → CIDR → IP → domain fallback
- [x] 1.3 Implement domain pattern validation (RFC 1123 labels, single-label domains allowed, single leftmost wildcard only, last label must contain alphabetic character)
- [x] 1.4 Implement port validation (1–65535 numeric or `*` wildcard)
- [x] 1.5 Implement config validation: no duplicate `(target-pattern, port-pattern)` identity, no mixed port patterns per target
- [x] 1.6 Implement domain matching (exact match, single-level wildcard per RFC 9525, case-insensitive)
- [x] 1.7 Implement IP/CIDR matching (exact IP as implicit /32 or /128, CIDR range containment, IPv4-mapped IPv6 normalization)
- [x] 1.8 Implement resolution: single-dimension target specificity (label count for domains, prefix length for CIDRs), protocol compatibility check, port match, default-deny
- [x] 1.9 Add fuzz tests for `Parse()` and resolution

## 2. Config — route `net:` rules

- [x] 2.1 Extend config to route `net:` prefixed rules to `netrules.Parse()`, store parsed rules in `Config.NetRules`
- [x] 2.2 Add `Config.HasNetRules() bool` method
- [x] 2.3 Run net rule config validation (duplicate identity, mixed port patterns) at config load time
- [x] 2.4 Reject unknown resource prefixes (not `fs:` or `net:`) with error

## 3. Access log — network operation types

- [x] 3.1 Add `HTTPS` and `HTTP` operation types to `internal/accesslog/`
- [x] 3.2 Verify deduplication works for network entries with `(operation, target)` key

## 4. Proxy — forward proxy on UDS

- [x] 4.1 Create `internal/proxy/` package with `Proxy` type that listens on a UDS
- [x] 4.2 Implement CONNECT handler: extract host:port, check allowlist, dial target, respond 200/403, bidirectional relay
- [x] 4.3 Implement plain HTTP handler: extract host:port (default port 80), check allowlist, forward request (strip hop-by-hop headers), relay response
- [x] 4.4 Implement malformed request handling (non-HTTP bytes → 400, missing host → 400)
- [x] 4.5 Implement `Allowlist` type using net rules for target+port matching with single-dimension target specificity
- [x] 4.6 Integrate access log: feed each request as entry with operation, target, result, and matching rule
- [x] 4.7 Implement proxy lifecycle: `Start()` creates UDS and begins accepting, `Stop()` closes listener, drains in-flight connections with timeout, removes UDS

## 5. Tunnel — TCP-to-UDS bridge

- [x] 5.1 Create `internal/tunnel/` package with `Run()` function that listens on `127.0.0.1:0`, bridges TCP to UDS
- [x] 5.2 Set `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` env vars to `http://127.0.0.1:<port>`; unset `NO_PROXY` and `no_proxy`
- [x] 5.3 Run user command as subprocess, propagate exit code
- [x] 5.4 Drain in-flight relay goroutines when user command exits before tunnel exits
- [x] 5.5 Fail-closed: if listener bind fails or UDS is inaccessible, exit non-zero without running user command

## 6. Sandbox — bwrap changes and proxy lifecycle

- [x] 6.1 Remove `--share-net` from `BuildBwrapArgs` unconditionally
- [x] 6.2 When net rules present: create temp dir for UDS, bind-mount UDS and execave binary into sandbox (read-only), wrap command with `execave network-tunnel`
- [x] 6.3 Integrate proxy lifecycle: start proxy before bwrap execution, stop proxy after bwrap exits, clean up temp dir
- [x] 6.4 Update monitor setup phase detection: 3 execve calls when net rules present, 2 otherwise

## 7. CLI — tunnel subcommand

- [x] 7.1 Add `network-tunnel` cobra subcommand to `cmd/execave/main.go`
- [x] 7.2 Wire access log logger to both monitor and proxy

## 8. E2E tests

- [x] 8.1 Test full network isolation without net rules (connection fails, DNS fails)
- [x] 8.2 Test allowed HTTPS domain via proxy (CONNECT succeeds for allowlisted domain)
- [x] 8.3 Test denied HTTPS domain via proxy (CONNECT returns 403 for non-allowlisted domain)
- [x] 8.4 Test allowed/denied IP and CIDR matching
- [x] 8.5 Test wildcard domain matching (one-level only, no apex, no deep subdomain)
- [x] 8.6 Test deny override (exact domain beats wildcard, longer CIDR beats shorter)
- [x] 8.7 Test port filtering (exact port, wildcard port, wrong port denied)
- [x] 8.8 Test plain HTTP forwarding (allowed and denied)
- [x] 8.9 Test IPv6 rules
- [x] 8.10 Test access log contains network entries (`HTTPS`/`HTTP` operations with correct format)
- [x] 8.11 Test direct connection fails even with net rules (process ignoring HTTP_PROXY has no NIC)
- [x] 8.12 Test exit code propagation through tunnel

## 9. Documentation

- [x] 9.1 Update `docs/security-model.md`: add network isolation guarantees, attacks & mitigations, remove "no network isolation" limitation
- [x] 9.2 Update `docs/architecture.md`: add proxy-tunnel architecture, UDS path, process lifecycle
- [x] 9.3 Update `README.md` and `execave.json.example` with `net:` rule examples
- [x] 9.4 Add `openspec/specs/net-rules/spec.md`
- [x] 9.5 Update `openspec/specs/fs-rules/spec.md` and `openspec/specs/access-log/spec.md` with network-related changes
- [x] 9.6 Update `openspec/config.yaml` context section
