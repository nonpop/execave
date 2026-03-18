## Why

Pass rules for proxy-related env vars (`HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`, `no_proxy`) are silently useless: the tunnel always strips these from the inherited environment and injects its own values. A user adding `pass:HTTP_PROXY` or `pass:NO_PROXY` gets no error but the host value never reaches the sandboxed command. The README compounds this by suggesting `NO_PROXY` can be set "via env rules", which is impossible (env rules only support `pass`, and the tunnel strips the result anyway).

## What Changes

- Reject pass rules targeting any of the 6 proxy env vars at parse time with a clear error message explaining the tunnel manages these vars.
- Fix README to remove the misleading "or via env rules" suggestion for setting `NO_PROXY`.

This change restricts the sandbox configuration surface (rejects previously-silent misconfiguration). Not a breaking change in practice since these rules had no effect.

## Playbooks

### New Playbooks

_(none)_

### Modified Playbooks

- `filtering-environment`: Add use case for the new config error when proxy vars are used in pass rules.

## Capabilities

### New Capabilities

_(none)_

### Modified Capabilities

- `env-rules`: Add requirement that proxy-managed variable names are rejected at parse time.

## Impact

- `internal/envrules/envrules.go` — new validation in `ParseRule`
- `README.md` — fix intra-sandbox servers paragraph
- `test/e2e/cli_rules_test.go` — new error test cases
