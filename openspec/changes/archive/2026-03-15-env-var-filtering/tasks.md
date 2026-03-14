## 1. E2E Tests (write first)

- [x] 1.1 Add e2e test: default-deny — host env var absent in sandbox without env rules
- [x] 1.2 Add e2e test: `pass:HOME` rule — host HOME visible inside sandbox
- [x] 1.3 Add e2e test: multiple pass rules — only listed vars visible, others absent
- [x] 1.4 Add e2e test: no-sandbox mode — all host env vars pass through unfiltered
- [x] 1.5 Add e2e test: secret not visible inside sandbox even with net rules (preventing-sandbox-escape scenario)
- [x] 1.6 Add e2e test: invalid env rule action rejected at config load
- [x] 1.7 Add e2e test: duplicate env rule rejected at config load
- [x] 1.8 Add e2e test: `config show` includes env section with provenance comments

## 2. `internal/envrules` Package

- [x] 2.1 Create `internal/envrules/envrules.go` with `Rule` struct (`Name`, `RawRule`, `SourcePath`), `Canonical()` method, `ParseRule()`, and `ValidateRules()`
- [x] 2.2 Create `internal/envrules/resolver.go` with `Resolver`, `NewResolver()`, and `Resolve(environ []string) []string`
- [x] 2.3 Write component tests for `ParseRule`: valid pass rule, empty name, invalid action, missing colon
- [x] 2.4 Write component tests for `ValidateRules`: duplicate rejected, different names allowed
- [x] 2.5 Write component tests for `Resolve`: match, multiple match, absent skipped, empty rules, empty value, non-matching excluded

## 3. Config Integration

- [x] 3.1 Add `Env []string` to `rawConfig` in `internal/config/config.go`
- [x] 3.2 Add `EnvRules []envrules.Rule` to `Config` struct
- [x] 3.3 Add env rule parse loop + `envrules.ValidateRules` call in `buildConfig()`
- [x] 3.4 Add `mergeEnvRules()` following the dedup pattern of existing merge functions; call from `mergeConfigs()`
- [x] 3.5 Add `renderEnvRules()` and `appendSection` call for `env` key in `internal/config/render.go`
- [x] 3.6 Write component tests for config: valid env rules parsed, empty env section, invalid action rejected, duplicate rejected, ParseTOML with env rules

## 4. Sandbox Integration

- [x] 4.1 Add `--clearenv` to bwrap args in `buildBwrapArgs()` in `internal/sandbox/sandbox.go`
- [x] 4.2 Construct `envrules.NewResolver(cfg.EnvRules)` and call `Resolve(os.Environ())` in `buildBwrapArgs()`; append `--setenv KEY VALUE` for each result
- [x] 4.3 Write component tests for sandbox: default-deny (clearenv present, no setenv), pass rule injects var, absent host var not injected, multiple vars injected

## 5. Documentation

- [x] 5.1 Update `docs/security-model.md`: change env var row from "None" to env-rules mitigation; update limitations section
- [x] 5.2 Update `README.md` and `docs/architecture.md` to mention `env` config section and `internal/envrules/` package
- [x] 5.3 Update `openspec/config.yaml` context section to reflect env filtering capability
