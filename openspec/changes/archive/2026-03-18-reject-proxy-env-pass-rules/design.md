## Context

The tunnel binary (running as PID 1 inside the sandbox's network namespace) always strips all six proxy-related env vars (`HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`, `no_proxy`) from the environment before exec-ing the user command, and injects its own `HTTP_PROXY`/`HTTPS_PROXY` pointing to the in-sandbox TCP bridge. This means any `pass:HTTP_PROXY` or `pass:NO_PROXY` rule silently has no effect — the host value is stripped regardless.

The README incorrectly suggests using env rules to set `NO_PROXY` for intra-sandbox servers, which is impossible with only `pass` semantics and pointless given the tunnel's stripping.

## Goals / Non-Goals

**Goals:**
- Reject `pass` rules for proxy-managed env var names at parse time with a clear, actionable error message.
- Fix the README to remove the misleading "via env rules" suggestion.

**Non-Goals:**
- Adding a `set:NAME=VALUE` rule type to allow users to inject arbitrary env vars.
- Changing how NO_PROXY works for intra-sandbox servers (the workaround is still to prefix the command, e.g. `NO_PROXY=localhost mycommand`).

## Decisions

### Reject at `ParseRule`, not `ValidateRules`

The proxy var names are inherently invalid for `pass` rules (the tunnel always overrides them) — not contextually invalid depending on other rules. This parallels how `ParseRule` already rejects invalid action prefixes and empty names. Failing at parse time gives earlier, more precise errors.

Comparison with other rule types:
- `fsrules.ParseRule` rejects invalid permission strings at parse time.
- `netrules.ParseRule` rejects structurally invalid domains at parse time.
- `syscallrules.ValidateRules` defers name validation because validity depends on the external `seccomp.RuleableSyscallNames()` set. That external dependency doesn't apply here.

### Fixed set of 6 names, hardcoded in `envrules`

The 6 names match exactly what `tunnel.buildEnv` strips: `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`, `no_proxy`. This is a stable, documented set tied to Go's `net/http` proxy conventions. No need for dynamic registration.

### Error message

The error must explain *why* the rule is invalid so users understand what to do instead. Proposed format:
```
env rule "pass:HTTP_PROXY": HTTP_PROXY is managed by the tunnel and cannot be passed from the host
```

## Risks / Trade-offs

- **Breaking change (benign)**: Configs that previously silently accepted `pass:HTTP_PROXY` will now fail. Since the rule had no effect, the only impact is users with a misguided rule in their config must remove it. The error message is actionable.
- **Case sensitivity**: The 6 names are case-exact matches. `pass:http_proxy` is rejected; `pass:Http_Proxy` would not be (this is not a real convention and not worth special-casing).
