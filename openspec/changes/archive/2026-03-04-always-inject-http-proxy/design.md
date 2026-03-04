## Context

`setupNetworking` in `cmd/execave/main.go` guards proxy+tunnel startup with:
```go
if !cfg.HasNetRules() && !monitorEnabled {
    return nil, nil, nil, nil
}
```
This means `HTTP_PROXY` is injected only when the user configures net rules or enables monitoring, requiring conditional language in all documentation and user-facing notes. The proxy already starts with a deny-all empty rule set for monitoring-without-net-rules, so the infrastructure for unconditional startup exists.

## Goals / Non-Goals

**Goals:**
- Remove the conditional so the proxy+tunnel starts on every `execave` invocation.
- Make `HTTP_PROXY`/`HTTPS_PROXY`/`http_proxy`/`https_proxy` injection unconditional.
- Simplify docs to drop all "when net rules or monitoring are active" qualifiers.

**Non-Goals:**
- Changing the proxy's rule-enforcement behavior (deny-all with no rules stays).
- Changing kernel-level network isolation (`--unshare-all` stays).
- Any performance optimization of the proxy/tunnel path.

## Decisions

### Remove the early-return guard entirely

**Decision:** Delete the `if !cfg.HasNetRules() && !monitorEnabled { return nil, nil, nil, nil }` guard in `setupNetworking`. The proxy starts unconditionally with whatever rule set (possibly empty) the config provides.

**Rationale:** The guard was an optimization to skip overhead when no networking was needed. With it gone, every run incurs the cost of starting a proxy and tunnel. This is acceptable: the overhead is a few goroutines and a Unix socket, negligible compared to bwrap/strace startup.

**Security analysis:** Removing the guard does not weaken the sandbox. Network isolation is still enforced by `--unshare-all` at the kernel level. The proxy operating in deny-all mode (no net rules) produces the same network outcome as having no proxy: all HTTP-proxy-aware connections are rejected (403 from proxy instead of ECONNREFUSED). Non-proxy-aware connections still fail (no NIC). No bypass scenario is introduced.

**Alternatives considered:**
- *Keep the guard, update docs with conditional language* — defeats the stated goal.
- *Add a `--no-proxy` flag to opt out* — unnecessary complexity; the overhead is trivial.

### No spec changes to sandbox/proxy/tunnel packages

**Decision:** The sandbox, proxy, and tunnel package specs require no modifications. Their requirements are conditioned on "when NetworkPath is provided" or "when the tunnel runs" — both still accurate. The change is purely at the CLI wiring layer (`setupNetworking`), which is not covered by any package-level spec.

**Exception:** The sandbox spec contains a note referencing `MonitoringWithoutNetRulesStartsProxyTunnel` — an artifact of the old conditional. Update it to reflect the new unconditional behavior.

## Risks / Trade-offs

- **Slight startup overhead without net rules** → Negligible; proxy+tunnel startup is fast.
- **`HTTP_PROXY` now always set — may surprise users who run intra-sandbox servers** → Already documented: use `NO_PROXY=localhost,127.0.0.1` or `--noproxy localhost` to bypass. Behavior is more predictable with the unconditional model.
- **Monitoring-without-net-rules behavior appears to change** → It doesn't: monitoring already triggered proxy startup. The change only affects the no-monitoring/no-net-rules case, which is now promoted to the same behavior.

## Migration Plan

Single-commit change: remove the guard in `setupNetworking`, update docs. No config format change, no rollback needed — the change is backwards-compatible.
