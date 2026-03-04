## 1. Implementation

- [x] 1.1 In `cmd/execave/main.go`, remove the `if !cfg.HasNetRules() && !monitorEnabled { return nil, nil, nil, nil }` early-return guard from `setupNetworking` so the proxy+tunnel starts unconditionally.

## 2. Spec sync

- [x] 2.1 In `openspec/specs/sandbox/spec.md`, update the "Proxy-tunnel path setup" requirement: replace the `MonitoringWithoutNetRulesStartsProxyTunnel` note with the new note from the delta spec, and rename the scenario label from "Net rules trigger proxy-tunnel setup" to "Proxy-tunnel setup".

## 3. Tests

- [x] 3.1 Update `TestE2E_RestrictingNetwork_RunCommandWithNoNetworkAccess` in `test/e2e/restricting_network_test.go` to use curl and assert that curl receives a non-2xx response (403) from the deny-all proxy, matching the MODIFIED use case.

## 4. Docs

- [x] 4.1 In `docs/architecture.md`, remove the conditional network startup language: collapse the two "Runtime (without net rules …)" Data Flow entries into one, and update the Tunnel section note about intra-sandbox connectivity to drop the "when net rules or monitoring are active" qualifier.
- [x] 4.2 In `README.md`, update "Network is isolated by default" and the "Intra-sandbox servers" note to remove the conditional "when net rules (or `--monitor`) are active" qualifier.
- [x] 4.3 In `openspec/config.yaml`, update the context section to reflect that the proxy+tunnel now starts unconditionally.
