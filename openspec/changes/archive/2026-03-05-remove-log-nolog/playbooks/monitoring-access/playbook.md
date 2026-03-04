## MODIFIED Use Cases

### Use Case: Write access log to file

The user writes the access log to a file, useful when TUI apps cover the terminal.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave --monitor=access.log -- vim src/main.go`
- **AND** the sandboxed command accesses files
- **THEN** `access.log` is created in the current directory
- **AND** entries are written to the file as they occur (tailable with `tail -f access.log`)
- **AND** each line contains result, operation, target path (shortened), and matched rule
- **AND** by default only DENY and UNKNOWN entries are written (OK entries are hidden)
- **AND** filesystem paths are shortened (relative to config dir, or `~/` form)

## REMOVED Use Cases

### Use Case: Suppress expected denies with fs:nolog
**Reason**: log/nolog visibility rules removed as unnecessary complexity.
**Migration**: No replacement; accept that harmless deny entries appear in the log, or filter output externally (e.g., `grep`).

### Use Case: Override nolog with fs:log for a subtree
**Reason**: log/nolog visibility rules removed as unnecessary complexity.
**Migration**: No replacement.

### Use Case: Suppress expected network denies with net:nolog
**Reason**: log/nolog visibility rules removed as unnecessary complexity.
**Migration**: No replacement; accept that harmless network deny entries appear in the log, or filter output externally.

### Use Case: Override net:nolog with net:log for specific endpoint
**Reason**: log/nolog visibility rules removed as unnecessary complexity.
**Migration**: No replacement.

### Use Case: Toggle to show nolog-suppressed entries
**Reason**: log/nolog visibility rules and `--show-nolog` flag removed.
**Migration**: No replacement.

### Use Case: Both filters are independent
**Reason**: log/nolog visibility rules removed; only the `--show-allowed` filter remains.
**Migration**: No replacement.

### Use Case: Log rule specificity matches access rule semantics for fs
**Reason**: log/nolog visibility rules removed.
**Migration**: No replacement.

### Use Case: Log rule specificity matches access rule semantics for net
**Reason**: log/nolog visibility rules removed.
**Migration**: No replacement.

### Use Case: Show nolog entries in text log
**Reason**: log/nolog visibility rules and `--show-nolog` flag removed.
**Migration**: No replacement.

### Use Case: Filter flags control text log output
**Reason**: With nolog removed, this use case duplicates "Show allowed entries in text log".
**Migration**: Use `--show-allowed` to include OK entries (as covered by the remaining use case).

### Use Case: Text log applies both filters independently
**Reason**: log/nolog visibility rules removed; only `--show-allowed` filter remains.
**Migration**: No replacement.
