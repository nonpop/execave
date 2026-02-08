## ADDED Requirements

### Requirement: Non-existent path filtering for reads

Read operations to paths that do not exist on the host filesystem SHALL NOT be logged. This filters noise from programs probing nonexistent paths (library search paths, config fallbacks). Write operations to nonexistent paths SHALL be logged, as they represent the program's intent to create files.

#### Scenario: Non-existent read filtered from log

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/noexist.txt` does not exist on the host filesystem
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process attempts to read `<tmp>/mount/noexist.txt`
- **THEN** the read fails
- **AND** log does NOT contain an entry for `<tmp>/mount/noexist.txt`

#### Scenario: Non-existent write logged

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/newfile.txt` does not exist on the host filesystem
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process attempts to write `<tmp>/mount/newfile.txt`
- **THEN** the write fails (read-only)
- **AND** log contains `WRITE <tmp>/mount/newfile.txt DENY`

#### Scenario: Stat error other than ENOENT still logged (fail-safe)

- **WHEN** monitoring is enabled
- **AND** `<tmp>/restricted/secret.txt` exists but `os.Stat` fails with permission denied
- **AND** config contains `fs:ro:<tmp>`
- **AND** sandboxed process attempts to read `<tmp>/restricted/secret.txt`
- **THEN** log contains `READ <tmp>/restricted/secret.txt DENY` (fail-safe: when in doubt, log it)

## MODIFIED Requirements

### Requirement: Symlink path resolution in access logging

When a path does not exist on the host filesystem, the resolver SHALL NOT attempt symlink resolution for that path. Non-existent paths are not symlinks and MUST be treated as literal paths.

#### Scenario: Non-existent path not resolved

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/noexist.txt` does not exist on the host filesystem
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process attempts to read `<tmp>/mount/noexist.txt`
- **THEN** the read fails
- **AND** log does NOT contain an entry for `<tmp>/mount/noexist.txt`
