## MODIFIED Requirements

### Requirement: Log format

Each log entry SHALL be a structured record with fields:
- Operation: `READ`, `WRITE`, `HTTPS`, or `HTTP`
- Target: the path accessed (for filesystem operations) or `host:port` (for network operations)
- Result: `OK`, `DENY`, or `UNKNOWN` (access cannot be evaluated against config rules, e.g., unresolvable relative path)
- Rule: the matching rule (e.g., `fs:ro:/etc` or `net:https:api.anthropic.com:443`) or an exception (e.g., `no-matching-rule`)

Network entries use `HTTPS` for CONNECT-tunneled requests and `HTTP` for plain HTTP requests. The proxy feeds network entries to the same logger that receives filesystem entries from the monitor.

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

#### Scenario: Allowed HTTPS request logged
- **WHEN** Logger receives entry (HTTPS, `api.example.com:443`, OK, `net:https:api.example.com:443`)
- **THEN** Entries() returns entry: Operation=`HTTPS`, Target=`api.example.com:443`, Result=`OK`, Rule=`net:https:api.example.com:443`

#### Scenario: Denied HTTPS request logged
- **WHEN** Logger receives entry (HTTPS, `malicious.example.com:443`, DENY, `no-matching-rule`)
- **THEN** Entries() returns entry: Operation=`HTTPS`, Target=`malicious.example.com:443`, Result=`DENY`, Rule=`no-matching-rule`

#### Scenario: Allowed HTTP request logged
- **WHEN** Logger receives entry (HTTP, `localhost:3000`, OK, `net:http:localhost:3000`)
- **THEN** Entries() returns entry: Operation=`HTTP`, Target=`localhost:3000`, Result=`OK`, Rule=`net:http:localhost:3000`

#### Scenario: Denied HTTP request logged
- **WHEN** Logger receives entry (HTTP, `localhost:3000`, DENY, `no-matching-rule`)
- **THEN** Entries() returns entry: Operation=`HTTP`, Target=`localhost:3000`, Result=`DENY`, Rule=`no-matching-rule`
