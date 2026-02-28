## MODIFIED Requirements

### Requirement: Log format

The Result field now also accepts `UNENFORCED`, indicating that no sandbox enforcement was active and the access was observed but not controlled.

MODIFIED: Result: `OK`, `DENY`, `UNKNOWN`, or `UNENFORCED`

#### Scenario: Unenforced entry logged

- **WHEN** Logger receives entry (READ, `/tmp/secret`, UNENFORCED, `no-matching-rule`)
- **THEN** Entries() returns entry: Operation=`READ`, Target=`/tmp/secret`, Result=`UNENFORCED`, Rule=`no-matching-rule`

#### Scenario: Unenforced entry with matching rule logged

- **WHEN** Logger receives entry (HTTP, `api.example.com:443`, UNENFORCED, `net:http:api.example.com:443`)
- **THEN** Entries() returns entry: Operation=`HTTP`, Target=`api.example.com:443`, Result=`UNENFORCED`, Rule=`net:http:api.example.com:443`

## ADDED Requirements

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
