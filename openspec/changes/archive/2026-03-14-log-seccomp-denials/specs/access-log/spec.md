## MODIFIED Requirements

### Requirement: Log format

Each log entry SHALL be a structured record with fields:
- Operation: `READ`, `WRITE`, `HTTP`, or `SYSCALL`
- Target: the path accessed (for filesystem operations), `host:port` (for network operations), or the syscall name (for blocked syscall operations)
- Result: `OK`, `DENY`, or `UNKNOWN` (access cannot be evaluated against config rules, e.g., unresolvable relative path)
- Rule: the matching rule (e.g., `fs:ro:/etc`, `net:http:api.anthropic.com:443`, `syscall:allow:bpf`) or an exception (e.g., `no-matching-rule`, `seccomp`)

Network entries use `HTTP` for all network requests (both CONNECT-tunneled and plain HTTP). The proxy feeds network entries to the same logger that receives filesystem entries from the monitor.

Syscall entries use `SYSCALL` for blocked syscall attempts. Denied entries use rule `seccomp`. Allowed entries (via `syscall:allow` config rules) use the matching rule string (e.g., `syscall:allow:bpf`).

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

#### Scenario: Seccomp-denied syscall logged
- **WHEN** Logger receives entry (SYSCALL, `bpf`, DENY, `seccomp`)
- **THEN** Entries() returns entry: Operation=`SYSCALL`, Target=`bpf`, Result=`DENY`, Rule=`seccomp`

#### Scenario: Allowed syscall logged
- **WHEN** Logger receives entry (SYSCALL, `bpf`, OK, `syscall:allow:bpf`)
- **THEN** Entries() returns entry: Operation=`SYSCALL`, Target=`bpf`, Result=`OK`, Rule=`syscall:allow:bpf`

#### Scenario: Syscall entries deduplicated
- **WHEN** Logger receives entry (SYSCALL, `bpf`, DENY, `seccomp`) twice
- **THEN** Entries() returns exactly one entry

#### Scenario: Syscall entries not filtered by managed paths
- **WHEN** Logger is configured with managed paths `/dev`, `/proc`, `/tmp`
- **AND** Logger receives entry (SYSCALL, `mount`, DENY, `seccomp`)
- **THEN** Entries() returns the entry (syscall targets are names, not paths)
