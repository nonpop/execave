# Access Log Capability

## Purpose

The access-log capability handles formatting, deduplication, and filtering of access entries. It transforms raw access events (filesystem and network) into structured log entries, eliminates redundant entries, and filters out infrastructure paths that are not governed by user rules.

## Requirements

### Requirement: Log format

Each log entry SHALL be a structured record with fields:
- Operation: `READ`, `WRITE`, or `HTTP`
- Target: the path accessed (for filesystem operations) or `host:port` (for network operations)
- Result: `OK`, `DENY`, `UNKNOWN` (access cannot be evaluated against config rules, e.g., unresolvable relative path), or `UNENFORCED` (no sandbox enforcement was active; access was observed but not controlled)
- Rule: the matching rule (e.g., `fs:ro:/etc` or `net:http:api.anthropic.com:443`) or an exception (e.g., `no-matching-rule`)

Network entries use `HTTP` for all network requests (both CONNECT-tunneled and plain HTTP). The proxy feeds network entries to the same logger that receives filesystem entries from the monitor.

#### Scenario: Allowed read logged
- **WHEN** Logger receives entry (READ, `/tmp/data/file.txt`, OK, `fs:ro:/tmp/data`)
- **THEN** Entries() returns entry: Operation=`READ`, Target=`/tmp/data/file.txt`, Result=`OK`, Rule=`fs:ro:/tmp/data`

#### Scenario: Denied write logged
- **WHEN** Logger receives entry (WRITE, `/tmp/project/.git/config`, DENY, `fs:ro:/tmp/project/.git`)
- **THEN** Entries() returns entry: Operation=`WRITE`, Target=`/tmp/project/.git/config`, Result=`DENY`, Rule=`fs:ro:/tmp/project/.git`

#### Scenario: No-access rule logged
- **WHEN** Logger receives entry (READ, `/tmp/project/.env`, DENY, `fs:none:/tmp/project/.env`)
- **THEN** Entries() returns entry: Operation=`READ`, Target=`/tmp/project/.env`, Result=`DENY`, Rule=`fs:none:/tmp/project/.env`

#### Scenario: No matching rule logged
- **WHEN** Logger receives entry (READ, `/tmp/secret`, DENY, `no-matching-rule`)
- **THEN** Entries() returns entry: Operation=`READ`, Target=`/tmp/secret`, Result=`DENY`, Rule=`no-matching-rule`

#### Scenario: Unresolved relative path logged
- **WHEN** Logger receives entry (READ, `foo/bar.txt`, UNKNOWN, `unresolved-relative-path`)
- **THEN** Entries() returns entry: Operation=`READ`, Target=`foo/bar.txt`, Result=`UNKNOWN`, Rule=`unresolved-relative-path`

#### Scenario: Allowed network request logged
- **WHEN** Logger receives entry (HTTP, `api.example.com:443`, OK, `net:http:api.example.com:443`)
- **THEN** Entries() returns entry: Operation=`HTTP`, Target=`api.example.com:443`, Result=`OK`, Rule=`net:http:api.example.com:443`

#### Scenario: Denied network request logged
- **WHEN** Logger receives entry (HTTP, `malicious.example.com:443`, DENY, `no-matching-rule`)
- **THEN** Entries() returns entry: Operation=`HTTP`, Target=`malicious.example.com:443`, Result=`DENY`, Rule=`no-matching-rule`

#### Scenario: Allowed HTTP request logged
- **WHEN** Logger receives entry (HTTP, `localhost:3000`, OK, `net:http:localhost:3000`)
- **THEN** Entries() returns entry: Operation=`HTTP`, Target=`localhost:3000`, Result=`OK`, Rule=`net:http:localhost:3000`

#### Scenario: Denied HTTP request logged
- **WHEN** Logger receives entry (HTTP, `localhost:3000`, DENY, `no-matching-rule`)
- **THEN** Entries() returns entry: Operation=`HTTP`, Target=`localhost:3000`, Result=`DENY`, Rule=`no-matching-rule`

#### Scenario: Unenforced entry logged

- **WHEN** Logger receives entry (READ, `/tmp/secret`, UNENFORCED, `no-matching-rule`)
- **THEN** Entries() returns entry: Operation=`READ`, Target=`/tmp/secret`, Result=`UNENFORCED`, Rule=`no-matching-rule`

#### Scenario: Unenforced entry with matching rule logged

- **WHEN** Logger receives entry (HTTP, `api.example.com:443`, UNENFORCED, `net:http:api.example.com:443`)
- **THEN** Entries() returns entry: Operation=`HTTP`, Target=`api.example.com:443`, Result=`UNENFORCED`, Rule=`net:http:api.example.com:443`

### Requirement: Log deduplication

Each unique `(operation, target, result)` tuple SHALL be logged at most once, regardless of how many times Log is called. Read and write to the same path are distinct tuples.

#### Scenario: Repeated reads deduplicated
- **WHEN** Logger receives the same READ entry three times
- **THEN** output contains exactly one READ line

#### Scenario: Read and write both logged
- **WHEN** Logger receives a READ entry and a WRITE entry for the same target
- **THEN** output contains one READ line and one WRITE line (two lines total)

#### Scenario: Repeated HTTP requests deduplicated
- **WHEN** Logger receives the same HTTP entry three times
- **THEN** output contains exactly one HTTP line

#### Scenario: Repeated writes deduplicated
- **WHEN** Logger receives the same WRITE entry three times
- **THEN** output contains exactly one WRITE line

### Requirement: Infrastructure path filtering

When configured with managed paths (e.g., `/dev`, `/proc`, `/tmp`), the Logger SHALL silently drop entries whose target is a managed path or a descendant of one.

#### Scenario: Infrastructure paths not logged
- **WHEN** Logger is configured with managed paths `/dev`, `/proc`, `/tmp`
- **AND** Logger receives entry (READ, `/proc/self/status`, OK, `fs:ro:/proc`)
- **THEN** output is empty

#### Scenario: Infrastructure writes not logged
- **WHEN** Logger is configured with managed paths `/dev`, `/proc`, `/tmp`
- **AND** Logger receives entry (WRITE, `/dev/tty`, OK, `fs:rw:/dev`)
- **THEN** output is empty

#### Scenario: Non-infrastructure paths still logged
- **WHEN** Logger is configured with managed paths `/dev`, `/proc`, `/tmp`
- **AND** Logger receives entry (READ, `/usr/bin/bash`, OK, `fs:ro:/usr`)
- **THEN** output contains an entry for `/usr/bin/bash`

### Requirement: Unenforced mode

When constructed with `unenforced=true`, the Logger SHALL override the Result of every entry passed to `Log()` to `ResultUnenforced`, regardless of the result supplied by the caller. This allows callers (monitor, proxy) to log entries without being aware of the no-sandbox mode.

#### Scenario: Logger in unenforced mode overrides result

- **WHEN** Logger is constructed with `unenforced=true`
- **AND** Logger receives entry (READ, `/home/user/file.txt`, DENY, `no-matching-rule`)
- **THEN** Entries() returns entry with Result=`UNENFORCED`

#### Scenario: Logger in normal mode preserves result

- **WHEN** Logger is constructed with `unenforced=false`
- **AND** Logger receives entry (READ, `/home/user/file.txt`, DENY, `no-matching-rule`)
- **THEN** Entries() returns entry with Result=`DENY`
