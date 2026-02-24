## 1. Core: Remove HTTPS protocol and operation type

- [x] 1.1 Remove `ProtocolHTTPS` from `internal/netrules/netrules.go`. Update `parseProtocol()` to accept only "http" and "none", with error message listing valid options. Update package godoc if it references HTTPS.
- [x] 1.2 Remove `OperationHTTPS` from `internal/accesslog/accesslog.go`. Update `Entry.Operation` godoc to list only READ, WRITE, HTTP.
- [x] 1.3 Update `internal/proxy/proxy.go` `handleCONNECT`: change `ProtocolHTTPS` → `ProtocolHTTP` and `OperationHTTPS` → `OperationHTTP`.
- [x] 1.4 Update `internal/webui/server.go`: change `case accesslog.OperationHTTPS, accesslog.OperationHTTP:` → `case accesslog.OperationHTTP:`.

## 2. Unit and integration tests

- [x] 2.1 Update `internal/netrules/netrules_test.go`: change HTTPS parse tests to expect errors, update valid-rule tests to use "http" action.
- [x] 2.2 Update `internal/netrules/resolver_test.go`: replace `ProtocolHTTPS` with `ProtocolHTTP`, remove tests that verify HTTPS/HTTP protocol distinction (the "HTTPS rule does not match HTTP request" / "HTTP rule does not match HTTPS request" cases).
- [x] 2.3 Update `internal/netrules/integration_test.go`: change all `net:https:` to `net:http:`, remove HTTPS-specific protocol matching test functions.
- [x] 2.4 Update `internal/netrules/fuzz_test.go`: remove `ProtocolHTTPS` from fuzz inputs. Run affected fuzz targets for 30 seconds.
- [x] 2.5 Update `internal/proxy/proxy_test.go`: replace `OperationHTTPS` with `OperationHTTP`.
- [x] 2.6 Update `internal/proxy/integration_test.go`: change `net:https:` rules to `net:http:`, update `OperationHTTPS` assertions.
- [x] 2.7 Update `internal/accesslog/accesslog_test.go`: replace `OperationHTTPS` with `OperationHTTP`.
- [x] 2.8 Update `internal/accesslog/integration_test.go`: replace `OperationHTTPS` with `OperationHTTP`.
- [x] 2.9 Update `internal/webui/integration_test.go`: replace `OperationHTTPS` with `OperationHTTP`.
- [x] 2.10 Update `internal/config/config_test.go`: change `net:https:` rules to `net:http:`.

## 3. E2E tests

- [x] 3.1 Update `test/e2e/restricting_network_test.go`: change `net:https:` to `net:http:`.
- [x] 3.2 Update `test/e2e/configuring_execave_test.go`: change `net:https:` to `net:http:`.
- [x] 3.3 Update `test/e2e/monitoring_access_test.go`: change `net:https:` to `net:http:`, replace HTTPS operation assertions with HTTP.
- [x] 3.4 Update `test/e2e/preventing_sandbox_escape_test.go`: change `net:https:` to `net:http:`.

## 4. Documentation

- [x] 4.1 Update `docs/security-model.md`: add "Plaintext over CONNECT tunnel" to Attacks & Mitigations table, add HTTPS enforcement limitation to Limitations section, update remaining HTTPS references.
- [x] 4.2 Update `docs/architecture.md`: update proxy description.
- [x] 4.3 Update `README.md`: change protocol list to "http" or "none", update `net:https:` example to `net:http:`, update access log example.

## 5. OpenSpec

- [x] 5.1 Sync delta specs to main specs (`openspec sync specs --change remove-https-protocol`).
- [x] 5.2 Sync delta playbooks to main playbooks (`openspec sync playbooks --change remove-https-protocol`).
- [x] 5.3 Update `openspec/config.yaml` context section if it references HTTPS protocol.
- [x] 5.4 Update active change `openspec/changes/log-visibility-rules/specs/net-rules/spec.md` line 75: change `https:example.com:443` to `http:example.com:443` in the cross-namespace validation scenario.

## 6. Verification

- [x] 6.1 `go build -o ./bin/execave ./cmd/execave` — compiles without errors.
- [x] 6.2 `go test ./...` — all tests pass.
- [x] 6.3 `golangci-lint run --fix` — no lint errors.
