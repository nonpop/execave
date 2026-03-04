## Why

The proxy-tunnel bridge currently starts only when net rules are configured or `--monitor` is active. This creates a conditional: `HTTP_PROXY` is sometimes set and sometimes not, forcing documentation and users to reason about "when" rather than "always". Always starting the proxy simplifies the mental model and makes docs unconditionally accurate.

## What Changes

- Remove the `!cfg.HasNetRules() && !monitorEnabled` early-return guard in `setupNetworking` in `cmd/execave/main.go` — the proxy+tunnel now starts unconditionally.
- Without net rules the proxy starts with an empty (deny-all) rule set, same as it already does for monitoring-without-net-rules today.
- `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` are always injected into the sandboxed process's environment; `NO_PROXY`/`no_proxy` are always unset.
- Update docs (`README.md`, `docs/architecture.md`) to drop all conditional language.

No security regression: network isolation is still kernel-enforced (`--unshare-all`). The proxy being deny-all without rules produces the same outcome as having no proxy at all — all connections fail. Processes that bypass `HTTP_PROXY` still have no NIC.

## Playbooks

### New Playbooks

*(none)*

### Modified Playbooks

- `restricting-network`: The "no network access (default-deny)" use case changes: `HTTP_PROXY` is now always set, so HTTP-proxy-aware clients receive `403 Forbidden` from the deny-all proxy instead of `ECONNREFUSED`/`ENETUNREACH`. The user-visible outcome (network access blocked) is unchanged, but the failure mode for proxy-aware clients differs.

## Capabilities

### New Capabilities

*(none)*

### Modified Capabilities

*(none — the sandbox, proxy, and tunnel specs are conditioned on NetworkPath being provided or on what happens when the tunnel runs, neither of which changes. The removal of the conditional is entirely in the CLI startup layer, not in any capability's requirements.)*

## Impact

- `cmd/execave/main.go`: Remove early-return in `setupNetworking`.
- `README.md`, `docs/architecture.md`: Drop conditional "when net rules or monitoring are active" language from network and tunnel descriptions.
- Minor: the Data Flow section in `docs/architecture.md` can collapse "without net rules, no monitoring" and "without net rules, monitoring enabled" into a single "no net rules" case.
