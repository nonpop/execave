## 1. Security-first groundwork

- [ ] 1.1 Read `docs/security-model.md` and capture invariants that must remain unchanged (sandbox boundary, default-deny behavior, config protection guarantees).
- [ ] 1.2 Review `docs/error-handling.md` and define layered-config error message format that includes operation context plus source config paths.

## 2. Layered config loading and path resolution

- [ ] 2.1 Extend config TOML parsing to accept optional `extends` entries and normalize each entry using fs-style path rules (absolute, relative to declaring file, tilde expansion).
- [ ] 2.2 Implement recursive extends loading with cycle detection based on canonical absolute config paths.
- [ ] 2.3 Ensure each loaded config file is parsed and validated independently with existing single-file rules before merge.

## 3. Merge, provenance, and final validation

- [ ] 3.1 Implement layered rule union that removes only exact duplicate rules and is order-independent.
- [ ] 3.2 Attach rule provenance (source config file path) through merge/final validation so conflict errors can report both rule texts and source files.
- [ ] 3.3 Run final merged validation using the same validators as single-file load for fs/net/syscall behavior.
- [ ] 3.4 Extend config-file protection checks to all loaded config file paths (root + parents), preserving explicit-writable rejection semantics.

## 4. Sandbox config-protection alignment

- [ ] 4.1 Update sandbox/config handoff so forced read-only protection remains correct for layered configs and cannot be bypassed through parent-file writability.
- [ ] 4.2 Add regression coverage for inherited-writable cases to verify layered configs still result in read-only mounts for config files at runtime.

## 5. Tests and verification

- [ ] 5.1 Add/update integration tests for new config spec scenarios: extends composition, path resolution, cycle rejection, exact-dedup acceptance, cross-file fs/net conflicts, source-aware errors, and parent/root config writability rejection.
- [ ] 5.2 Add/update E2E tests for modified playbook use cases in `configuring-execave` and `iterating-config` (including cross-file conflict remediation flow).
- [ ] 5.3 Run affected fuzz target(s) for config parsing/validation for at least 30 seconds and record failures if any.
- [ ] 5.4 Run full test suite (`go test ./...`) and resolve regressions caused by layered config changes.

## 6. Documentation and examples

- [ ] 6.1 Update `README.md`, `docs/architecture.md`, and `docs/security-model.md` with layered config behavior, threat implications, and troubleshooting guidance for source-aware conflicts.
- [ ] 6.2 Update config examples to include `extends` usage with absolute, relative, and tilde paths.
