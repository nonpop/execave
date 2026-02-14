# Access Log Capability

## Purpose

The access-log capability handles formatting, deduplication, and filtering of access entries. It transforms raw access events (filesystem and network) into structured log entries, eliminates redundant entries, and filters out infrastructure paths that are not governed by user rules.

## Requirements

### Requirement: Log format

Each log entry SHALL be a single line containing four space-separated fields: `<OP> <TARGET> <RESULT> <RULE>` where:
- `<OP>` is `READ`, `WRITE`, `HTTPS`, or `HTTP`
- `<TARGET>` is the path accessed (for filesystem operations) or `host:port` (for network operations)
- `<RESULT>` is `OK`, `DENY`, or `UNKNOWN` (access cannot be evaluated against config rules, e.g., unresolvable relative path)
- `<RULE>` is the matching rule (e.g., `fs:ro:/etc` or `net:https:api.anthropic.com:443`) or an exception (e.g., `no-matching-rule`)

Network entries use `HTTPS` for CONNECT-tunneled requests and `HTTP` for plain HTTP requests. The proxy feeds network entries to the same logger that receives filesystem entries from the monitor.

#### Scenario: Allowed read logged
- **WHEN** Logger receives entry (READ, `/tmp/data/file.txt`, OK, `fs:ro:/tmp/data`)
- **THEN** output contains: `READ /tmp/data/file.txt OK fs:ro:/tmp/data`

#### Scenario: Denied write logged
- **WHEN** Logger receives entry (WRITE, `/tmp/project/.git/config`, DENY, `fs:ro:/tmp/project/.git`)
- **THEN** output contains: `WRITE /tmp/project/.git/config DENY fs:ro:/tmp/project/.git`

#### Scenario: No-access rule logged
- **WHEN** Logger receives entry (READ, `/tmp/project/.env`, DENY, `fs:none:/tmp/project/.env`)
- **THEN** output contains: `READ /tmp/project/.env DENY fs:none:/tmp/project/.env`

#### Scenario: No matching rule logged
- **WHEN** Logger receives entry (READ, `/tmp/secret`, DENY, `no-matching-rule`)
- **THEN** output contains: `READ /tmp/secret DENY no-matching-rule`

#### Scenario: Unresolved relative path logged
- **WHEN** Logger receives entry (READ, `foo/bar.txt`, UNKNOWN, `unresolved-relative-path`)
- **THEN** output contains: `READ foo/bar.txt UNKNOWN unresolved-relative-path`

#### Scenario: Allowed HTTPS request logged
- **WHEN** Logger receives entry (HTTPS, `api.example.com:443`, OK, `net:https:api.example.com:443`)
- **THEN** output contains: `HTTPS api.example.com:443 OK net:https:api.example.com:443`

#### Scenario: Denied HTTPS request logged
- **WHEN** Logger receives entry (HTTPS, `malicious.example.com:443`, DENY, `no-matching-rule`)
- **THEN** output contains: `HTTPS malicious.example.com:443 DENY no-matching-rule`

#### Scenario: Allowed HTTP request logged
- **WHEN** Logger receives entry (HTTP, `localhost:3000`, OK, `net:http:localhost:3000`)
- **THEN** output contains: `HTTP localhost:3000 OK net:http:localhost:3000`

#### Scenario: Denied HTTP request logged
- **WHEN** Logger receives entry (HTTP, `localhost:3000`, DENY, `no-matching-rule`)
- **THEN** output contains: `HTTP localhost:3000 DENY no-matching-rule`

### Requirement: Log deduplication

Each unique `(operation, target, result)` tuple SHALL be logged at most once, regardless of how many times Log is called. Read and write to the same path are distinct tuples. `HTTPS` and `HTTP` to the same `host:port` are distinct tuples.

#### Scenario: Repeated reads deduplicated
- **WHEN** Logger receives the same READ entry three times
- **THEN** output contains exactly one READ line

#### Scenario: Read and write both logged
- **WHEN** Logger receives a READ entry and a WRITE entry for the same target
- **THEN** output contains one READ line and one WRITE line (two lines total)

#### Scenario: Repeated HTTPS requests deduplicated
- **WHEN** Logger receives the same HTTPS entry three times
- **THEN** output contains exactly one HTTPS line

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
