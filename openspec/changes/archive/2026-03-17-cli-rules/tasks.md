## 1. E2E tests for CLI rule use cases

- [x] 1.1 Add table-driven E2E test for CLI rule type flags (`--fs`, `--net`, `--syscall`, `--env`) augmenting a config file (each flag type is one table row)
- [x] 1.2 Add E2E test for `--extends` flag (adds a base config via CLI, with and without `--no-config`)
- [x] 1.3 Add E2E test for `--no-config` (CLI-only with inline rules, CLI-only with `--extends`)
- [x] 1.4 Add E2E test for `--config` + `--no-config` mutual exclusion error
- [x] 1.5 Add table-driven E2E test for CLI/config conflict errors (fs duplicate path, net duplicate identity) and CLI rule deduplication (same rule in CLI and config is silently accepted)
- [x] 1.6 Add table-driven E2E test for `config show` with CLI rules (provenance `# <cli>`) and with `--no-config`
- [x] 1.7 Add table-driven E2E test for invalid CLI rule syntax rejection (bad --fs, --net, --syscall, --env)
- [x] 1.8 Add E2E test for CLI fs path expansion (relative `./` and tilde `~/`)
- [x] 1.9 Add E2E test for CLI flags with `monitor` command
- [x] 1.10 Update existing "missing config file" E2E test to add a `--no-config` sub-case verifying no config file is required

## 2. CLI flag definitions

- [x] 2.1 Add `--fs`, `--net`, `--syscall`, `--env`, `--extends` as `StringArrayVar` persistent flags on root command
- [x] 2.2 Add `--no-config` as `BoolVar` persistent flag on root command
- [x] 2.3 Add `PersistentPreRunE` to validate `--config` / `--no-config` mutual exclusion
- [x] 2.4 Add `CLIRules` struct to `run` package and wire CLI flag values into `SandboxConfig`
- [x] 2.5 Update `runCommand` and `monitorCommand` to populate `CLIRules` from flags
- [x] 2.6 Update `configShowCommand` to populate `CLIRules` from flags

## 3. SourcePath sentinel constants

- [x] 3.1 Add `SourceCLI` and `SourceSynthetic` named constants to `config` package
- [x] 3.2 Replace `SourcePath = ""` with `SourceSynthetic` in `config.go` (`appendForcedReadOnlyRules`, `appendSyntheticRORule`)
- [x] 3.3 Update `orderedSourcePaths` and `appendSection` in `render.go` to use `SourceSynthetic` (remove hardcoded empty-string check; add `SourceSynthetic` to `ConfigPaths` so `orderedSourcePaths` picks it up automatically)
- [x] 3.4 Update existing tests that assert on empty-string SourcePath

## 4. Config loading with CLI rules

- [x] 4.1 Add `LoadWithCLI` function to `config` package that builds virtual rawConfig from CLI rules + optional config file path
- [x] 4.2 Use `SourceCLI` as SourcePath for CLI-parsed rules; use cwd as configDir
- [x] 4.3 Add sentinel values to `Config.ConfigPaths` when rules with that source exist (file paths → `SourceCLI` → `SourceSynthetic`)
- [x] 4.4 Wire `LoadRuntimeConfig` to call `LoadWithCLI` when CLI rules are present, passing through managed paths, interpreter, tunnel binary, and UDS path
- [x] 4.5 Handle `--no-config` case in `LoadRuntimeConfig`: skip config file, use only CLI rules and extends
- [x] 4.6 Add integration tests for `LoadWithCLI` covering: merge, dedup, conflict errors, CLI-only, extends, path resolution, SourcePath provenance

## 5. Config show rendering

- [x] 5.1 Update `orderedSourcePaths` in `render.go` to use `SourceCLI` and `SourceSynthetic` constants instead of hardcoded empty-string checks
- [x] 5.2 Add integration test for `RenderEffectiveTOML` with CLI-sourced rules showing `# <cli>` provenance

## 6. Documentation

- [x] 6.1 Update `docs/architecture.md` and `docs/security-model.md` to cover CLI rule flags
- [x] 6.2 Update `README.md` usage examples with CLI rule flags and `--no-config`
- [x] 6.3 Update `openspec/config.yaml` context section
