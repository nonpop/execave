## 1. [SECURITY] Preparation

- [x] 1.1 Read `docs/security-model.md` — understand trust boundaries, default-deny model, and "Symlinks can't escape" guarantee before modifying resolution logic
- [x] 1.2 Read `docs/error-handling.md` — resolution errors must follow `operation context: wrapped-error` format

## 2. Resolver: types and component-by-component walk

Strict TDD: write failing tests first, then implement.

- [x] 2.1 **Test:** `TestCheckAccess_SymlinkWithinMount` — symlink within a rule's scope is resolved; `result.Symlink` is non-nil with one hop, `ResolvedPath` equals the target, main `Allowed`/`Rule` reflect the target
- [x] 2.2 **Test:** `TestCheckAccess_RuleBoundarySymlink` — symlink whose path exactly matches a rule path is not resolved; `result.Symlink` is nil
- [x] 2.3 **Test:** `TestCheckAccess_RuleBoundarySymlinkIntermediateComponent` — intermediate directory symlink matching a rule path is not resolved; access to descendant works via unresolved path
- [x] 2.4 **Test:** `TestCheckAccess_SymlinkChainMultiHop` — multi-hop chain within a rule; `result.Symlink.Hops` has one entry per intermediate symlink, all allowed
- [x] 2.5 **Test:** `TestCheckAccess_SymlinkChainDeniedHop` — chain breaks at hop with no matching rule; hop marked denied, main result denied, `ResolvedPath` empty
- [x] 2.6 **Test:** `TestCheckAccess_SymlinkEscapesMount` — symlink within a rule pointing to path outside any rule; hop OK, target DENY
- [x] 2.7 **Test:** `TestCheckAccess_SymlinkDepthLimit` — symlink loop exceeds 40 hops; result denied
- [x] 2.8 **Test:** `TestCheckAccess_SymlinkIntermediateComponent` — symlink in middle path component within a rule; resolved correctly, hop logged
- [x] 2.9 **Test:** `TestCheckAccess_SymlinkWriteThroughToReadOnly` — write through symlink in rw rule to target in ro rule; symlink hop OK (read), target DENY (write)
- [x] 2.9b **Test:** `TestCheckAccess_SymlinkWriteThroughReadOnlyLinkToWritableTarget` — write through symlink in ro rule to target in rw rule; symlink hop OK (read), target OK (write)
- [x] 2.10 **Test:** `TestCheckAccess_NonExistentPathNotResolved` — non-existent path within a rule; `Symlink` is nil, result based on original path
- [x] 2.10b **Test:** `TestCheckAccess_SymlinkThroughManagedPath` — symlink pointing into a managed path; `Uncertain` is true, chain is `Unresolvable`
- [x] 2.10c **Test:** `TestCheckAccess_SymlinkChainThroughManagedPath` — multi-hop chain entering a managed path; `Uncertain` is true, hops before managed area are recorded
- [x] 2.11 **Test:** existing `TestCheckAccess_RuleAttribution` "no matching rule" subtest — assert `result.Symlink` is nil
- [x] 2.12 **Implement:** add `SymlinkChain` and `SymlinkHop` types to `internal/rules/resolver.go`; add `Symlink *SymlinkChain` field to `AccessResult`
- [x] 2.13 **Implement:** replace `resolveSymlinks` (`filepath.EvalSymlinks`) with component-by-component walk in `CheckAccess`: split path into components, `os.Lstat` each, detect symlinks, distinguish rule-boundary vs within-rule, `os.Readlink` for within-rule symlinks, handle absolute/relative targets, depth limit of 40, ENOENT = stop resolving, other errors = deny
- [x] 2.14 **Implement:** add `isRuleBoundary` helper — returns true when the accumulated path exactly matches a rule path (not just as a prefix)
- [x] 2.14b **Implement:** add `isUnresolvablePath` helper — returns true when path is under a managed path where host-side resolution is unreliable
- [x] 2.14c **Implement:** add `Unresolvable` field to `SymlinkChain`, `Uncertain` field to `AccessResult`; detect managed path targets in `resolvePathComponents`
- [x] 2.15 **Verify:** `go test ./internal/rules/...` — all new and existing tests pass
- [x] 2.16 **Fuzz:** run `go test -fuzz=FuzzCheckAccess -fuzztime=30s ./internal/rules/` and `go test -fuzz=FuzzCheckAccessWithOverlappingRules -fuzztime=30s ./internal/rules/` — no regressions

## 3. Monitor: multi-entry symlink logging

Strict TDD: write failing tests first, then implement.

- [x] 3.1 **Test:** `TestMonitor_SymlinkWithinMount` (synthetic strace data) — strace line reads a symlink path within a rule; log contains `READ <link>` hop entry + `READ <target>` target entry
- [x] 3.2 **Test:** `TestMonitor_SymlinkDeniedTarget` (synthetic strace data) — symlink within rule pointing outside rules; log contains `READ <link> OK` + `READ <target> DENY no-matching-rule`
- [x] 3.3 **Test:** `TestMonitor_SymlinkWriteOperation` (synthetic strace data) — write to a symlink path; log contains `READ <link> OK` (hop) + `WRITE <target> OK` (target with original op)
- [x] 3.3b **Test:** `TestMonitor_SymlinkWriteThroughReadOnlyLink` (synthetic strace data) — write to symlink in ro dir pointing to rw dir; log contains `READ <link> OK` (hop) + `WRITE <target> OK` (target with original op)
- [x] 3.4 **Test:** `TestMonitor_SymlinkTargetDeduplicated` (synthetic strace data) — two symlinks to same target; second access to target is deduplicated
- [x] 3.5 **Implement:** update `processAccessEntry` in `internal/monitor/monitor.go` — when `result.Symlink` is non-nil, emit one `READ` entry per hop (each with own `isFirstEntryFor`/`isManagedPath` check), then emit `<OP> <resolved-path>` entry for the target if all hops were readable
- [x] 3.5b **Test:** `TestMonitor_SymlinkThroughManagedPath` (synthetic strace data) — symlink into a managed path; log contains `READ <link> UNKNOWN symlink-target-unresolvable`
- [x] 3.5c **Implement:** add `RuleSymlinkTargetUnresolvable` constant; handle `result.Uncertain` in `processAccessEntry` — log original path with `UNKNOWN` result
- [x] 3.6 **Verify:** `go test ./internal/monitor/...` — all new and existing tests pass

## 4. E2E tests

One test per spec scenario. Tests use `createSymlink` helper, run bwrap+strace via `runMonitored`, assert both sandbox behavior and log content.

- [x] 4.1 `TestE2E_Monitor_RuleBoundarySymlinkLoggedWithoutResolution`
- [x] 4.2 `TestE2E_Monitor_RuleBoundarySymlinkInIntermediateComponentLoggedWithoutResolution`
- [x] 4.3 `TestE2E_Monitor_SymlinkWithinMountResolvedAndLogged`
- [x] 4.4 `TestE2E_Monitor_SymlinkWithinMountPointingOutsideRulesDenied`
- [x] 4.5 `TestE2E_Monitor_MultiHopSymlinkChainWithinMount`
- [x] 4.6 `TestE2E_Monitor_MultiHopChainBreaksAtDeniedIntermediateHop`
- [x] 4.7 `TestE2E_Monitor_SymlinkInIntermediatePathComponentResolved`
- [x] 4.8 `TestE2E_Monitor_WriteOperationThroughSymlinkWithinMount`
- [x] 4.9 `TestE2E_Monitor_WriteThroughSymlinkToReadOnlyTargetDenied`
- [x] 4.9b `TestE2E_Monitor_WriteThroughReadOnlySymlinkToWritableTargetAllowed`
- [x] 4.10 `TestE2E_Monitor_SymlinkDepthLimitExceeded`
- [x] 4.11 `TestE2E_Monitor_ResolvedSymlinkPathsDeduplicated`
- [x] 4.12 `TestE2E_Monitor_NonExistentPathNotResolved`
- [x] 4.13 `TestE2E_Monitor_SymlinkThroughManagedPathLoggedAsUnknown`

## 5. Verification

- [x] 5.1 `go test ./...` — all tests pass
- [x] 5.2 `golangci-lint run --fix` — clean
- [x] 5.3 Run fuzz targets for 30s each: `FuzzCheckAccess`, `FuzzCheckAccessWithOverlappingRules`, `FuzzMatchesPath`
