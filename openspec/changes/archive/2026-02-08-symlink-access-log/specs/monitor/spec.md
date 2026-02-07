## ADDED Requirements

### Requirement: Symlink path resolution in access logging

When the accessed path contains symlinks, the monitor SHALL resolve them component by component, matching how the kernel resolves paths inside bwrap's mount namespace. The monitor SHALL distinguish between symlinks at rule boundaries and symlinks within mounted directories:

- **Rule-boundary symlinks** (the symlink path exactly matches a config rule path): bwrap resolves these at mount time. The monitor SHALL NOT resolve them and SHALL log the access against the original (unresolved) path.
- **Symlinks within a rule's scope** (the symlink path is a descendant of a config rule path, or has no matching rule): the kernel resolves these at access time inside the sandbox. The monitor SHALL resolve them step by step, logging a `READ` entry for each symlink hop, followed by the final target access with the original operation.

If any hop in the resolution chain is denied (no matching rule or insufficient permission), the chain SHALL stop and subsequent hops and the final target SHALL NOT be logged.

The symlink resolution depth SHALL be limited to 40 links (matching the Linux kernel's `MAXSYMLINKS`). Exceeding this limit SHALL be treated as a denial.

The monitor's access log SHALL be consistent with sandbox enforcement: if the final relevant log entry for an access is `DENY`, the sandbox MUST have denied the operation; if `OK`, the sandbox MUST have allowed it.

#### Scenario: Rule-boundary symlink logged without resolution

- **WHEN** monitoring is enabled
- **AND** `<tmp>/link-file` is a symlink to `<tmp>/target-file`
- **AND** config contains `fs:ro:<tmp>/link-file`
- **AND** sandboxed process reads `<tmp>/link-file`
- **THEN** the read succeeds
- **AND** log contains: `READ <tmp>/link-file OK fs:ro:<tmp>/link-file`
- **AND** log does NOT contain an entry for `<tmp>/target-file`

#### Scenario: Rule-boundary symlink in intermediate component logged without resolution

- **WHEN** monitoring is enabled
- **AND** `<tmp>/link-dir` is a symlink to `<tmp>/real-dir`
- **AND** `<tmp>/real-dir/file.txt` exists
- **AND** config contains `fs:ro:<tmp>/link-dir`
- **AND** sandboxed process reads `<tmp>/link-dir/file.txt`
- **THEN** the read succeeds
- **AND** log contains: `READ <tmp>/link-dir/file.txt OK fs:ro:<tmp>/link-dir`
- **AND** log does NOT contain an entry for `<tmp>/real-dir/file.txt`

#### Scenario: Symlink within mount resolved and logged

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link.txt` is a symlink to `<tmp>/mount/target.txt`
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/link.txt`
- **THEN** the read succeeds
- **AND** log contains: `READ <tmp>/mount/link.txt OK fs:ro:<tmp>/mount`
- **AND** log contains: `READ <tmp>/mount/target.txt OK fs:ro:<tmp>/mount`

#### Scenario: Relative symlink within mount resolved and logged

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link.txt` is a relative symlink to `<tmp>/mount/target.txt`
- **AND** `<tmp>/mount/target.txt` is a regular file
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/link.txt`
- **THEN** the read succeeds
- **AND** log contains: `READ <tmp>/mount/link.txt OK fs:ro:<tmp>/mount`
- **AND** log contains: `READ <tmp>/mount/target.txt OK fs:ro:<tmp>/mount`

#### Scenario: Relative symlink chain resolved with all hops logged

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link` is a relative symlink to `<tmp>/mount/hop2`
- **AND** `<tmp>/mount/hop2` is a relative symlink to `<tmp>/mount/final.txt`
- **AND** `<tmp>/mount/final.txt` is a regular file
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/link`
- **THEN** the read succeeds
- **AND** log contains in order:
  - `READ <tmp>/mount/link OK fs:ro:<tmp>/mount`
  - `READ <tmp>/mount/hop2 OK fs:ro:<tmp>/mount`
  - `READ <tmp>/mount/final.txt OK fs:ro:<tmp>/mount`

#### Scenario: Symlink within mount pointing outside rules denied

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/escape.txt` is a symlink to `<tmp>/outside/secret.txt`
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** no rule matches `<tmp>/outside`
- **AND** sandboxed process reads `<tmp>/mount/escape.txt`
- **THEN** the read fails
- **AND** log contains: `READ <tmp>/mount/escape.txt OK fs:ro:<tmp>/mount`
- **AND** log contains: `READ <tmp>/outside/secret.txt DENY no-matching-rule`

#### Scenario: Multi-hop symlink chain within mount

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/hop1` is a symlink to `<tmp>/mount/hop2`
- **AND** `<tmp>/mount/hop2` is a symlink to `<tmp>/mount/final.txt`
- **AND** `<tmp>/mount/final.txt` is a regular file
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/hop1`
- **THEN** the read succeeds
- **AND** log contains in order:
  - `READ <tmp>/mount/hop1 OK fs:ro:<tmp>/mount`
  - `READ <tmp>/mount/hop2 OK fs:ro:<tmp>/mount`
  - `READ <tmp>/mount/final.txt OK fs:ro:<tmp>/mount`

#### Scenario: Multi-hop chain breaks at denied intermediate hop

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/hop1` is a symlink to `<tmp>/nomatch/hop2`
- **AND** `<tmp>/nomatch/hop2` is a symlink to `<tmp>/mount/final.txt`
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** no rule matches `<tmp>/nomatch`
- **AND** sandboxed process reads `<tmp>/mount/hop1`
- **THEN** the read fails
- **AND** log contains: `READ <tmp>/mount/hop1 OK fs:ro:<tmp>/mount`
- **AND** log contains: `READ <tmp>/nomatch/hop2 DENY no-matching-rule`
- **AND** log does NOT contain an entry for `<tmp>/mount/final.txt`

#### Scenario: Symlink in intermediate path component resolved

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/subdir-link` is a symlink to `<tmp>/mount/subdir-real`
- **AND** `<tmp>/mount/subdir-real/file.txt` exists
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/subdir-link/file.txt`
- **THEN** the read succeeds
- **AND** log contains: `READ <tmp>/mount/subdir-link OK fs:ro:<tmp>/mount`
- **AND** log contains: `READ <tmp>/mount/subdir-real/file.txt OK fs:ro:<tmp>/mount`

#### Scenario: Write operation through symlink within mount

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link.txt` is a symlink to `<tmp>/mount/real.txt`
- **AND** config contains `fs:rw:<tmp>/mount`
- **AND** sandboxed process writes to `<tmp>/mount/link.txt`
- **THEN** the write succeeds
- **AND** log contains: `READ <tmp>/mount/link.txt OK fs:rw:<tmp>/mount`
- **AND** log contains: `WRITE <tmp>/mount/real.txt OK fs:rw:<tmp>/mount`

#### Scenario: Write through symlink to read-only target denied

- **WHEN** monitoring is enabled
- **AND** `<tmp>/writable/link.txt` is a symlink to `<tmp>/readonly/file.txt`
- **AND** config contains `fs:rw:<tmp>/writable` and `fs:ro:<tmp>/readonly`
- **AND** sandboxed process writes to `<tmp>/writable/link.txt`
- **THEN** the write fails
- **AND** log contains: `READ <tmp>/writable/link.txt OK fs:rw:<tmp>/writable`
- **AND** log contains: `WRITE <tmp>/readonly/file.txt DENY fs:ro:<tmp>/readonly`

#### Scenario: Write through read-only symlink to writable target allowed

- **WHEN** monitoring is enabled
- **AND** `<tmp>/readonly/link.txt` is a symlink to `<tmp>/writable/file.txt`
- **AND** config contains `fs:ro:<tmp>/readonly` and `fs:rw:<tmp>/writable`
- **AND** sandboxed process writes to `<tmp>/readonly/link.txt`
- **THEN** the write succeeds
- **AND** log contains: `READ <tmp>/readonly/link.txt OK fs:ro:<tmp>/readonly`
- **AND** log contains: `WRITE <tmp>/writable/file.txt OK fs:rw:<tmp>/writable`

#### Scenario: Symlink depth limit exceeded

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/loop-a` is a symlink to `<tmp>/mount/loop-b`
- **AND** `<tmp>/mount/loop-b` is a symlink to `<tmp>/mount/loop-a`
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/loop-a`
- **THEN** the read fails
- **AND** the access is logged as denied
- **AND** log contains: `READ <tmp>/mount/loop-a DENY symlink-depth-limit-exceeded`
  (the hop that exceeded the limit is logged with a distinct reason)

#### Scenario: Resolved symlink paths deduplicated

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link1` and `<tmp>/mount/link2` are both symlinks to `<tmp>/mount/target.txt`
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/link1` then `<tmp>/mount/link2`
- **THEN** both reads succeed
- **AND** log contains exactly one `READ` entry for `<tmp>/mount/target.txt`

#### Scenario: Non-existent path not resolved

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/noexist.txt` does not exist on the host filesystem
- **AND** config contains `fs:ro:<tmp>/mount`
- **AND** sandboxed process attempts to read `<tmp>/mount/noexist.txt`
- **THEN** the read fails
- **AND** log contains: `READ <tmp>/mount/noexist.txt OK fs:ro:<tmp>/mount`

#### Scenario: Symlink through managed path logged as unknown

- **WHEN** monitoring is enabled
- **AND** `<tmp>/mount/link.txt` is a symlink to `/tmp/target.txt`
- **AND** config contains `fs:rw:<tmp>/mount`
- **AND** sandboxed process reads `<tmp>/mount/link.txt`
- **THEN** the read fails (target does not exist on sandbox tmpfs)
- **AND** log contains: `READ <tmp>/mount/link.txt UNKNOWN symlink-target-unresolvable`
