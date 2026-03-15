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

`errors.Is()` and `errors.As()` are used only with stdlib/OS types (`os.ErrClosed`,
`net.ErrClosed`, `syscall.EINTR`, `exec.ExitError`), never for custom sentinel errors.

## Cleanup Errors

Deferred cleanup errors that must not be silently dropped are accumulated with `errors.Join`:

```go
err = errors.Join(err, fmt.Errorf("stop proxy: %w", stopErr))
```

## Testing

- Component tests: `assert.ErrorContains(t, err, "substring")` to verify the right error occurred
- E2E tests: `assert.Contains(t, result.Stderr, "substring")` for user-visible messages

## Panics

Panics signal bugs, not runtime errors. A panic means the program has reached a state that
should be impossible in a correct implementation. End users may see the panic message, so it
must be understandable and actionable.

**Prefix:** every panic message starts with `"execave bug: "` so users know to report the issue.

### Categories

**Precondition violations** — documented in godoc with "must" or "panics if":

```go
// NewMonitor creates a monitor. setupExecCount must be non-negative.
func NewMonitor(setupExecCount int) *Monitor {
    if setupExecCount < 0 {
        panic("execave bug: monitor created with negative setup exec count")
    }
    ...
}
```

**Exhaustive switches / unhandled enum values** — a new value was added without updating all switch statements:

```go
switch opType {
case opRead:
    ...
case opWrite:
    ...
default:
    panic(fmt.Sprintf("execave bug: unhandled filesystem operation type %q", opType))
}
```

**Impossible runtime conditions** — errors that cannot occur without a bug in this code or its dependencies:

```go
panic("execave bug: close strace pipe after start: " + err.Error())
```

### Format

Use string concatenation for simple messages, `fmt.Sprintf` when including structured context:

```go
panic("execave bug: resolver received relative path: " + path)
panic(fmt.Sprintf("execave bug: unhandled permission type %d in rule check", perm))
```

## Security

- **No leakage:** Don't expose filesystem paths beyond what's in user-provided config
- **Audit trail:** Security-relevant errors must include enough context to reconstruct the operation
