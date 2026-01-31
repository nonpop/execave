# Error Handling Conventions

## Format

**Pattern:** `<operation> <identifiers>: <wrapped-error>`

Errors read like a stack trace—operation → context → root cause:

```
load config from /etc/execave.json: parse rule at index 2: invalid permission "invalid"
```

**Rules:**
- Use imperative verbs, not "failed to" (`load config`, not `failed to load config`)
- Include identifiers (paths, indices, names) for debugging and audit

```go
return fmt.Errorf("parse rule at index %d (%q): %w", i, rawRule, err)
return fmt.Errorf("invalid permission %q (must be 'ro', 'rw', or 'none')", perm)
```

## No Sentinel Errors

Use rich string errors with inline context. No `var Err... = errors.New(...)`.

This codebase has no `errors.Is()` checks—string errors provide better context without sentinel overhead.

## Testing

- Unit tests: `assert.ErrorContains(t, err, "substring")` to verify the right error occurred
- E2E tests: `assert.Contains(t, result.Stderr, "substring")` for user-visible messages

No `errors.Is()` checks.

## Security

- **No leakage:** Don't expose filesystem paths beyond what's in user-provided config
- **Audit trail:** Security-relevant errors must include enough context to reconstruct the operation
