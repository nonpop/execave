# Access Log Capability

## Purpose

The access-log capability handles formatting, deduplication, and filtering of access entries. It transforms raw access events (filesystem and network) into structured log entries, eliminates redundant entries, and filters out infrastructure paths that are not governed by user rules.

## Requirements

### Requirement: Log format

Each log entry SHALL be a single line in the format: `<OP> <TARGET> <RESULT> <RULE>` where:
- `<OP>` is `READ`, `WRITE`, `HTTPS`, or `HTTP`
- `<TARGET>` is the path accessed (for filesystem operations) or `host:port` (for network operations)
- `<RESULT>` is `OK`, `DENY`, or `UNKNOWN` (access cannot be evaluated against config rules, e.g., unresolvable relative path)
- `<RULE>` is the matching rule (e.g., `fs:ro:/etc` or `net:https:api.anthropic.com:443`) or an exception (e.g., `no-matching-rule`)

Network entries use `HTTPS` for CONNECT-tunneled requests and `HTTP` for plain HTTP requests. The proxy feeds network entries to the same logger that receives filesystem entries from the monitor.

#### Scenario: Allowed read logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process reads `<tmp>/data/file.txt`
- **AND** config contains `fs:ro:<tmp>/data`
- **THEN** log contains line: `READ <tmp>/data/file.txt OK fs:ro:<tmp>/data`

#### Scenario: Denied write logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process attempts to write `<tmp>/project/.git/config`
- **AND** config contains `fs:ro:<tmp>/project/.git`
- **THEN** log contains line: `WRITE <tmp>/project/.git/config DENY fs:ro:<tmp>/project/.git`

#### Scenario: No-access rule logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process attempts to read `<tmp>/project/.env`
- **AND** config contains `fs:none:<tmp>/project/.env`
- **THEN** log contains line: `READ <tmp>/project/.env DENY fs:none:<tmp>/project/.env`

#### Scenario: No matching rule logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process attempts to read `<tmp>/secret`
- **AND** no rule matches `<tmp>/secret`
- **THEN** log contains line: `READ <tmp>/secret DENY no-matching-rule`

#### Scenario: Unresolved relative path logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process accesses a relative path (e.g., `foo/bar.txt`)
- **AND** the fd path for the `*at()` syscall is unavailable
- **THEN** log contains line: `READ foo/bar.txt UNKNOWN unresolved-relative-path`

#### Scenario: Allowed HTTPS request logged
- **WHEN** monitoring is enabled
- **AND** proxy allows CONNECT request for `api.example.com:443`
- **AND** config contains `net:https:api.example.com:443`
- **THEN** log contains line: `HTTPS api.example.com:443 OK net:https:api.example.com:443`

#### Scenario: Denied HTTPS request logged
- **WHEN** monitoring is enabled
- **AND** proxy denies CONNECT request for `malicious.example.com:443`
- **AND** no matching rule exists
- **THEN** log contains line: `HTTPS malicious.example.com:443 DENY no-matching-rule`

#### Scenario: Allowed HTTP request logged
- **WHEN** monitoring is enabled
- **AND** proxy allows plain HTTP request for `localhost:3000`
- **AND** config contains `net:http:localhost:3000`
- **THEN** log contains line: `HTTP localhost:3000 OK net:http:localhost:3000`

#### Scenario: Denied HTTP logged without net rules
- **WHEN** monitoring is enabled
- **AND** config contains no `net:` rules
- **AND** sandboxed process attempts an HTTP request to `localhost:3000`
- **THEN** log contains line: `HTTP localhost:3000 DENY no-matching-rule`

### Requirement: Log deduplication

Each unique `(operation, target)` pair SHALL be logged at most once, regardless of how many times the access occurs. Read and write to the same path are distinct pairs. `HTTPS` and `HTTP` to the same `host:port` are distinct pairs.

#### Scenario: Repeated reads deduplicated
- **WHEN** monitoring is enabled
- **AND** sandboxed process reads `<tmp>/data/file.txt` three times
- **THEN** log contains exactly one READ entry for `<tmp>/data/file.txt`

#### Scenario: Read and write both logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process reads and writes `<tmp>/project/file.txt`
- **AND** config contains `fs:rw:<tmp>/project`
- **THEN** log contains one READ entry and one WRITE entry for the path (two lines total)

#### Scenario: Repeated HTTPS requests deduplicated
- **WHEN** monitoring is enabled
- **AND** proxy handles three CONNECT requests for `api.example.com:443`
- **THEN** log contains exactly one HTTPS entry for `api.example.com:443`

#### Scenario: Repeated writes deduplicated
- **WHEN** monitoring is enabled
- **AND** sandboxed process writes to `<tmp>/project/out.txt` multiple times
- **THEN** log contains exactly one WRITE entry for `<tmp>/project/out.txt`

### Requirement: Infrastructure path filtering

Infrastructure paths (`/dev`, `/proc`, `/tmp`) and their descendants SHOULD NOT be logged, as they are not governed by config rules.

#### Scenario: Infrastructure paths not logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process accesses `/proc/self/status`
- **THEN** log does NOT contain any entry for `/proc/self/status`

#### Scenario: Infrastructure writes not logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process writes to `/dev/tty`
- **THEN** log does NOT contain any entry for `/dev/tty`

#### Scenario: Filesystem paths still logged
- **WHEN** monitoring is enabled
- **AND** sandboxed process accesses `<tmp>/data/file.txt`
- **THEN** log contains an entry for `<tmp>/data/file.txt`
