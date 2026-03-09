# Godoc Style Guide

Target reader: an experienced developer new to this codebase, orienting for audit or modification.

## Baseline

Follow standard Go doc conventions:

- Start with the symbol name: `// Foo does X.`
- Present tense, active voice.
- Use `[Symbol]` cross-references for types, functions, and methods in the same or imported packages.

## Layering

- `docs/` covers system-level topics (architecture, security model, error handling, testing).
- Godoc covers package-level and symbol-level topics.
- No duplication across layers. Godoc assumes the reader has access to `docs/`.

## Package comments

Describe the package's role, boundaries, and key entry points. Do not repeat what individual symbol comments already say.

**Placement:** In the main `.go` file when obvious (e.g., `fsrules.go` for package fsrules). Use `doc.go` only when no clear main file exists.

## Symbol comments

Describe the symbol's **contract**: what callers can rely on.

- **Preconditions and postconditions.** Preconditions stated in godoc must have panic checks at function entry (per CLAUDE.md).
- **Error behavior.** When and what errors are returned.
- **Concurrency safety** when relevant.
- **Security rationale.** Briefly explain *why* when a choice exists for security reasons.

Do not describe how the implementation works — that belongs as inline comments in the function body.

## No repetition

- Package comments describe role and boundaries.
- Symbol comments describe the symbol's contract.
- They must not repeat each other. If the package comment mentions a function, it should say what role it plays, not restate the function's full contract.

## Coverage

- All exported symbols must have godoc comments.
- Unexported symbols: only when the code alone isn't enough for an experienced developer new to the codebase. Skip obvious helpers.
