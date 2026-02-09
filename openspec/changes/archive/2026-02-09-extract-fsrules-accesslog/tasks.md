## 1. Create `internal/fsrules` package

- [x] 1.1 Create `internal/fsrules/` directory with package declaration and godoc
- [x] 1.2 Move types from config: `Rule`, `Permission`, `Resource` (and their constants) into `fsrules/fsrules.go`
- [x] 1.3 Move `normalizePath` from config into fsrules
- [x] 1.4 Move `parseRule` from config into fsrules as the `Parse(rawRule, configDir string) (Rule, error)` entrypoint (parses a single `fs:<perm>:<path>` rule string, strips the `fs:` prefix internally)
- [x] 1.5 Move validation functions from config into fsrules: `Validate(rules []Rule, configPath string, managedPaths []string) error` wrapping `validateNoDuplicates`, `validateConfigNotWritable`, `validateNoManagedPaths`
- [x] 1.6 Move all of `internal/rules/resolver.go` into `fsrules/resolver.go`: `Resolver`, `Operation`, `AccessResult`, `SymlinkChain`, `SymlinkHop`, `CheckAccess`, `PermissionFor`, `findMatchingRule`, `matchesPath`, `resolvePathComponents`, `isRuleBoundary`, `isUnresolvablePath`, `checkPermission`. Update all references from `config.Rule`/`config.Permission` to the local types.
- [x] 1.7 Create `fsrules/export_test.go`: export `MatchesPath` (from old rules) and `ParseRule`/`NormalizePath` (from old config)
- [x] 1.8 Verify `go build ./internal/fsrules/...` compiles

## 2. Migrate fsrules tests

- [x] 2.1 Move `internal/rules/resolver_test.go` → `internal/fsrules/resolver_test.go`, update package name and imports
- [x] 2.2 Move `internal/rules/resolver_fuzz_test.go` → `internal/fsrules/resolver_fuzz_test.go`, update package name and imports
- [x] 2.3 Move config tests that test FS parsing/validation from `internal/config/config_test.go` into `internal/fsrules/fsrules_test.go` (tests for `parseRule`, `normalizePath`, `validateNoDuplicates`, `validateConfigNotWritable`, `validateNoManagedPaths`)
- [x] 2.4 Move FS-related fuzz targets from `internal/config/config_fuzz_test.go` into `internal/fsrules/fsrules_fuzz_test.go`
- [x] 2.5 Run `go test ./internal/fsrules/...` — all tests pass
- [x] 2.6 Run affected fuzz targets for at least 30 seconds each

## 3. Thin `internal/config`

- [x] 3.1 Change `Config` struct: replace `Rules []Rule` with `FSRules []fsrules.Rule`, add import for fsrules
- [x] 3.2 Remove moved types (`Rule`, `Permission`, `Resource`, `parseRule`, `normalizePath`, validation functions) from `config.go`
- [x] 3.3 Rewrite `config.Load` as thin router: split raw rules by first `:` prefix, route `fs:` to `fsrules.Parse()`, reject unknown prefixes, call `fsrules.Validate()`
- [x] 3.4 Update `config/export_test.go`: remove exports for moved functions (`ParseRule`, `NormalizePath`)
- [x] 3.5 Update remaining config tests in `config_test.go` (JSON loading, unknown resource type, config file not found) to use new `Config.FSRules` field
- [x] 3.6 Update `config_fuzz_test.go`: remove moved fuzz targets, keep any JSON-level fuzzing
- [x] 3.7 Run `go test ./internal/config/...` — all remaining tests pass

## 4. Delete `internal/rules`

- [x] 4.1 Delete `internal/rules/` directory (all files absorbed into fsrules)
- [x] 4.2 Verify no remaining imports of `internal/rules` anywhere: `go build ./...`

## 5. Update callers for `config.Rules` → `config.FSRules`

- [x] 5.1 Update `cmd/execave/main.go`: change `rules.New(cfg)` to `fsrules.NewResolver(cfg.FSRules, cfg.ManagedPaths)` (or equivalent), update imports
- [x] 5.2 Update `internal/sandbox/sandbox.go`: change references from `config.Rule`, `config.Permission`, `rules.New`, `rules.Resolver` to their fsrules equivalents
- [x] 5.3 Update `internal/sandbox/sandbox_test.go` if it references config types directly
- [x] 5.4 Update `internal/monitor/monitor.go`: change references from `config.Rule`, `rules.Resolver`, `rules.OperationRead`, `rules.OperationWrite` to fsrules equivalents
- [x] 5.5 Run `go build ./...` — full build succeeds
- [x] 5.6 Run `go test ./...` — all tests pass

## 6. Create `internal/accesslog` package

- [x] 6.1 Create `internal/accesslog/` directory with package declaration and godoc
- [x] 6.2 Move types from monitor: `OperationType` (READ, WRITE), `ResultType` (OK, DENY, UNKNOWN), rule-reason constants (`RuleNoMatch`, `RuleUnresolvedRelativePath`, `RuleSymlinkTargetUnresolvable`, `RuleSymlinkDepthExceeded`)
- [x] 6.3 Move `accessKey` struct and create `Logger` struct with `seen` map, `writer`, and `managed` paths
- [x] 6.4 Implement `New(writer io.Writer, managedPaths []string) *Logger` constructor
- [x] 6.5 Move `writeLogEntry` into Logger as internal formatting method
- [x] 6.6 Move `isManagedPath` into Logger as internal filtering method, parameterized by `managed` field
- [x] 6.7 Move non-existent read path filtering (`os.Stat` check) into Logger
- [x] 6.8 Move dedup logic (`alreadyLogged`) into Logger
- [x] 6.9 Implement `Log(entry Entry) error` that composes: managed path filter → dedup → non-existent read filter → format → write
- [x] 6.10 Create `Entry` type: `{Operation OperationType, Path string, Result ResultType, Rule string}`
- [x] 6.11 Create `accesslog/export_test.go`: export `IsManagedPath` and rule-reason constants for test use
- [x] 6.12 Verify `go build ./internal/accesslog/...` compiles

## 7. Migrate accesslog tests

- [x] 7.1 Move monitor tests that test log formatting, dedup, managed path filtering, and non-existent path filtering from `internal/monitor/monitor_test.go` into `internal/accesslog/accesslog_test.go`
- [x] 7.2 Run `go test ./internal/accesslog/...` — all tests pass

## 8. Thin `internal/monitor`

- [x] 8.1 Remove moved types and functions from `monitor.go`: `OperationType` (keep `OperationIgnored`), `ResultType`, rule-reason constants, `accessKey`, `writeLogEntry`, `isManagedPath`, `alreadyLogged`
- [x] 8.2 Replace `Monitor.seen` map with `*accesslog.Logger` field
- [x] 8.3 Rewrite `logPathAccess` to construct an `accesslog.Entry` and call `Logger.Log()`
- [x] 8.4 Rewrite `handleRelativePath`, `handleUncertainResult`, `handleDepthLimitExceeded`, `handleSymlinkChain` to construct entries and call `Logger.Log()`
- [x] 8.5 Update `Monitor.New` to accept `*accesslog.Logger` instead of raw `logPath`
- [x] 8.6 Update `monitor/export_test.go`: remove exports for moved functions/constants, keep strace-related exports
- [x] 8.7 Update remaining monitor tests in `monitor_test.go` to use accesslog types
- [x] 8.8 Run `go test ./internal/monitor/...` — all remaining tests pass

## 9. Wire up in CLI

- [x] 9.1 Update `cmd/execave/main.go`: create `accesslog.Logger` with `sandbox.ManagedDirs`, pass to monitor
- [x] 9.2 Run `go build ./...` — full build succeeds

## 10. Full verification

- [x] 10.1 Run `go test ./...` — all tests pass
- [x] 10.2 Run `golangci-lint run --fix` — no lint errors
- [x] 10.3 Run E2E tests: `go test ./test/e2e/...` — all pass with no changes to E2E test files
- [x] 10.4 Verify no import cycles: `go vet ./...`
- [x] 10.5 Verify dependency graph matches design: `fsrules` has no internal imports, `accesslog` has no internal imports, `config` imports `fsrules`, `monitor` imports `fsrules` + `accesslog`, `sandbox` imports `fsrules` (via config)

## 11. Documentation

- [x] 11.1 Update `docs/architecture.md` to reflect new package structure
- [x] 11.2 Verify godoc comments on all exported types/functions in `fsrules` and `accesslog`
- [x] 11.3 Update `openspec/config.yaml` to register new specs (`fs-rules`, `access-log`)

## 12. Reorganize E2E tests to match spec structure

- [x] 12.1 Create `test/e2e/fsrules_test.go` for fs-rules spec tests
- [x] 12.2 Move from `config_test.go` to `fsrules_test.go`: `TestE2E_Config_InvalidPermissionType`, `TestE2E_Config_MalformedRule`, rename to `TestE2E_FSRules_*`
- [x] 12.3 Move from `config_test.go` to `fsrules_test.go`: `TestE2E_Config_PathWithRelativeComponents`, `TestE2E_Config_TrailingSlashRemoval`, `TestE2E_Config_RelativePathResolution`, `TestE2E_Config_RelativePathWithParentTraversal`, rename to `TestE2E_FSRules_*`
- [x] 12.4 Move from `config_test.go` to `fsrules_test.go`: `TestE2E_Config_DuplicatePathsWithDifferentPermissions`, `TestE2E_Config_IdenticalDuplicateRules` and helper `assertDuplicatePathRejected`, rename to `TestE2E_FSRules_*`
- [x] 12.5 Move from `config_test.go` to `fsrules_test.go`: `TestE2E_Config_RuleTargetsManagedPathExactly`, `TestE2E_Config_RuleTargetsDescendantOfManagedPath`, `TestE2E_Config_PathWithManagedPrefixInNameIsAllowed`, rename to `TestE2E_FSRules_*`
- [x] 12.6 Move from `config_test.go` to `fsrules_test.go`: `TestE2E_Config_ConfigFileExplicitlyWritable`, rename to `TestE2E_FSRules_ConfigFileCannotBeExplicitlyWritable`
- [x] 12.7 Move from `sandbox_test.go` to `fsrules_test.go`: `TestE2E_Sandbox_SpecificRoOverridesGeneralRw`, `TestE2E_Sandbox_SpecificRwOverridesGeneralRo`, rename to `TestE2E_FSRules_MostSpecificRuleWins_*`
- [x] 12.8 Create `test/e2e/accesslog_test.go` for access-log spec tests
- [x] 12.9 Move from `monitor_test.go` to `accesslog_test.go`: `TestE2E_Monitor_AllowedReadLogged`, `TestE2E_Monitor_DeniedWriteLogged`, `TestE2E_Monitor_NoAccessRuleLogged`, `TestE2E_Monitor_NoMatchingRuleLogged`, `TestE2E_Monitor_UnresolvedRelativePathLogged`, rename to `TestE2E_AccessLog_LogFormat_*`
- [x] 12.10 Move from `monitor_test.go` to `accesslog_test.go`: `TestE2E_Monitor_RepeatedReadsDeduplicated`, `TestE2E_Monitor_ReadAndWriteBothLogged`, `TestE2E_Monitor_RepeatedWritesDeduplicated`, rename to `TestE2E_AccessLog_LogDeduplication_*`
- [x] 12.11 Move from `monitor_test.go` to `accesslog_test.go`: `TestE2E_Monitor_InfrastructurePathsNotLogged`, `TestE2E_Monitor_InfrastructureWritesNotLogged`, `TestE2E_Monitor_FilesystemPathsStillLogged`, `TestE2E_Monitor_SandboxSetupPathsNotLogged`, `TestE2E_Monitor_NamespaceOperationsNotLogged`, rename to `TestE2E_AccessLog_InfrastructurePathFiltering_*`
- [x] 12.12 Move from `monitor_test.go` to `accesslog_test.go`: `TestE2E_Monitor_NonExistentPathFilteredFromLog`, `TestE2E_Monitor_NonExistentPathNotResolved`, `TestE2E_Monitor_StatErrorStillLogged`, rename to `TestE2E_AccessLog_NonExistentPathFiltering_*`
- [x] 12.13 Update `config_test.go`: keep only config-level tests (default location, custom location, config not found, valid config, empty rules, unknown resource type)
- [x] 12.14 Update `monitor_test.go`: keep only monitor-level tests (enable/disable, custom log path, strace integration, symlink resolution, SIGINT handling)
- [x] 12.15 Update `sandbox_test.go`: keep only sandbox-level tests (permission enforcement, mount behavior, command execution, exit codes, config file protection)
- [x] 12.16 Run `go test ./test/e2e/...` — all tests pass with new organization
