## Context

Execave currently loads a single TOML config file and validates its `fs`, `net`, and `syscall` rule sections before sandbox startup. Teams now need reusable policy layers (shared base + project overlay) without duplicating rules across repositories.

This change affects config parsing and validation, which is security-critical because config content controls sandbox policy. The sandbox boundary itself (bwrap namespaces, mount behavior, seccomp, proxy enforcement) must remain unchanged; only rule ingestion and diagnostics are extended.

Trust boundaries remain the same as documented in `docs/security-model.md`: config is user-controlled trusted input to execave, and child processes are untrusted.

## Goals / Non-Goals

**Goals:**
- Support layered config composition via `extends = ["<path>", ...]`.
- Resolve `extends` paths using existing fs path semantics (absolute, relative-to-declaring-file, tilde expansion).
- Keep fail-safe behavior: each file must validate on its own, and merged rules must validate under the same rule constraints as a single file.
- Allow repeated shared rules across files only when they are exact duplicates.
- Provide source-aware final-validation errors so users can identify conflicting files quickly.
- Preserve config-file protection behavior for layered configs.

**Non-Goals:**
- No sandbox boundary change (no new namespaces, mounts, proxy behavior, or seccomp behavior).
- No implicit global config discovery; all parent files are explicit in `extends`.
- No compatibility shim for alternative `extends` syntaxes.
- No change to rule resolution semantics (longest-prefix fs, net specificity) once rules are loaded.

## Decisions

### Decision: Add recursive `extends` loading in config package

`internal/config` will load a root config, recursively resolve `extends`, and produce one merged rule set.

Why:
- Keeps composition logic in one place (the existing config trust boundary).
- Avoids touching sandbox/runner/proxy behavior.

Alternative considered:
- Resolve layering in CLI and pass flattened rules into config parser. Rejected: splits validation responsibilities and weakens auditability.

### Decision: `extends` path normalization matches fs rule path semantics

Each `extends` entry is normalized as:
- absolute path: unchanged
- relative path: joined against directory of the file that declares the entry
- `~` prefix: expanded to current user home

Why:
- Reuses existing user mental model for paths.
- Keeps behavior deterministic across nested layers.

Alternative considered:
- Resolve all relatives against the root config directory. Rejected: breaks locality and makes reused parent files context-dependent.

### Decision: Two-phase validation with strict merge model

Validation flow:
1. Parse and validate each config file independently with current single-file validation rules.
2. Build union of all parsed rules; remove only exact duplicate rules.
3. Validate the merged union using the same rule validators used for single-file configs.

Why:
- Maintains existing safety invariants and parser behavior.
- Ensures layered configs cannot bypass duplicate/conflict checks.
- Exact-dedup allows harmless repetition of shared rules while keeping strict failure on non-identical overlaps.

Alternative considered:
- Conflict-specific merge rules (e.g., “later layer wins”). Rejected: order-dependent policy is harder to audit and easier to misconfigure.

### Decision: Source-aware provenance is attached to parsed rules

Each parsed rule keeps source metadata (at minimum the absolute source config path) through merge/final validation so duplicate/conflict errors can report both rule and source file.

Why:
- Required for actionable errors in layered configs.
- Reduces operational risk from silent ambiguity in multi-file policy sets.

Alternative considered:
- Keep current errors and require manual tracing. Rejected: too costly for users and weak for security review workflows.

### Decision: Preserve config-file protection for all loaded config files

Layered loading treats every loaded config file path as protected:
- explicit writable rule against any loaded config file is rejected by validation
- inherited writability is still forced read-only at sandbox mount time

Why:
- Prevents future-run policy tampering regardless of which layer file is targeted.
- Maintains guarantees in `docs/security-model.md` (“Config file protected”).

Alternative considered:
- Protect only the root config. Rejected: parent config tampering would become a privilege-escalation path across runs.

## Risks / Trade-offs

- [Risk] Recursive loading introduces cycles or duplicate traversal bugs.  
  → Mitigation: DFS with canonical absolute paths and explicit cycle detection using active recursion stack.

- [Risk] Exact-dedup definition ambiguity could accidentally hide meaningful differences.  
  → Mitigation: define dedup key precisely in implementation/tests and keep final full validation enabled.

- [Risk] Source metadata leaks into user-facing logs where not desired.  
  → Mitigation: use dedicated provenance fields for validation errors; keep runtime access-log rule text unchanged.

- [Risk] Protecting all loaded config files may reject previously “working” but unsafe configs.  
  → Mitigation: keep behavior explicit in errors/docs and provide migration guidance in playbooks.

- [Risk] More files increase parse-time I/O and complexity.  
  → Mitigation: bounded recursion checks, deterministic traversal, and focused tests/fuzzing around parser inputs.

## Migration Plan

1. Implement layered parsing and path normalization behind existing `config.Load` entrypoint.
2. Add source-aware conflict diagnostics and update validation tests.
3. Extend config-protection handling to all loaded config paths and update sandbox integration tests.
4. Add/adjust E2E scenarios for extends success paths, cycles, and cross-file conflicts.
5. Update docs/examples (`README.md`, architecture/security docs, sample config).

Rollback:
- Revert layered loading path and return to single-file load semantics; no persistent data migration is required.

## Open Questions

- None at this stage; behavior decisions for merge, path resolution, and ordering were fixed during exploration.
