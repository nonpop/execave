# Text Log Capability

## Purpose

The text-log capability provides text-based access log output. It writes formatted access log entries to a file or stderr.

## Requirements

### Requirement: Text log entry format

The text log writer SHALL format each entry as a single line: `RESULT  OP  target  (rule)` followed by a newline. RESULT SHALL be left-padded to 10 characters (longest: `UNENFORCED`). OP SHALL be left-padded to 5 characters (longest: `WRITE`). The target and rule fields are unpadded.

#### Scenario: Deny entry formatted

- **WHEN** Writer receives entry (READ, `/home/user/.ssh/id_rsa`, DENY, `no-matching-rule`)
- **THEN** the output line is `DENY       READ   /home/user/.ssh/id_rsa  (no-matching-rule)`

#### Scenario: OK entry formatted

- **WHEN** Writer receives entry (HTTP, `api.example.com:443`, OK, `net:http:api.example.com:443`)
- **THEN** the output line is `OK         HTTP   api.example.com:443  (net:http:api.example.com:443)`

#### Scenario: Unknown entry formatted

- **WHEN** Writer receives entry (READ, `foo/bar.txt`, UNKNOWN, `unresolved-relative-path`)
- **THEN** the output line is `UNKNOWN    READ   foo/bar.txt  (unresolved-relative-path)`

### Requirement: Path shortening in text output

The text log writer SHALL shorten absolute filesystem target paths for display using the first applicable form in priority order: relative to configDir if under configDir, tilde form if under homeDir, otherwise absolute. Non-filesystem targets (HTTP entries) SHALL NOT be shortened.

#### Scenario: Filesystem path shortened to relative form

- **WHEN** configDir is `/home/user/project` and homeDir is `/home/user`
- **AND** Writer receives entry (READ, `/home/user/project/src/main.go`, OK, `fs:rw:~/project`)
- **THEN** the target in the output line is `src/main.go`

#### Scenario: Filesystem path shortened to tilde form

- **WHEN** configDir is `/home/user/project` and homeDir is `/home/user`
- **AND** Writer receives entry (READ, `/home/user/.ssh/id_rsa`, DENY, `no-matching-rule`)
- **THEN** the target in the output line is `~/.ssh/id_rsa`

#### Scenario: HTTP target not shortened

- **WHEN** Writer receives entry (HTTP, `api.example.com:443`, OK, `net:http:api.example.com:443`)
- **THEN** the target in the output line is `api.example.com:443` unchanged

### Requirement: Denied-only default filter

The text log writer SHALL hide entries with result OK by default. When `showAllowed` is true, OK entries SHALL be included in the output.

#### Scenario: OK entries hidden by default

- **WHEN** Writer is created with showAllowed=false
- **AND** Logger contains entries with results OK, DENY, and UNKNOWN
- **THEN** output contains only DENY and UNKNOWN entries

#### Scenario: OK entries shown when showAllowed is true

- **WHEN** Writer is created with showAllowed=true
- **AND** Logger contains entries with results OK, DENY, and UNKNOWN
- **THEN** output contains OK, DENY, and UNKNOWN entries

### Requirement: Nolog filter

The text log writer SHALL hide entries matching nolog rules by default. When `showNolog` is true, nolog entries SHALL be included in the output.

#### Scenario: Nolog entries hidden by default

- **WHEN** Writer is created with showNolog=false
- **AND** config contains `fs:nolog:/home/user/project/cache`
- **AND** Logger contains a DENY entry for `/home/user/project/cache/data`
- **THEN** output does not contain the entry

#### Scenario: Nolog entries shown when showNolog is true

- **WHEN** Writer is created with showNolog=true
- **AND** config contains `fs:nolog:/home/user/project/cache`
- **AND** Logger contains a DENY entry for `/home/user/project/cache/data`
- **THEN** output contains the entry

### Requirement: Independent filter axes

The denied-only filter and nolog filter SHALL operate independently. An entry MUST pass both filters to appear in the output.

#### Scenario: OK nolog entry hidden even with showAllowed

- **WHEN** Writer is created with showAllowed=true and showNolog=false
- **AND** config contains `fs:nolog:/usr/lib`
- **AND** Logger contains an OK entry for `/usr/lib/libc.so`
- **THEN** output does not contain the entry (blocked by nolog filter)

#### Scenario: Both filters disabled shows all entries

- **WHEN** Writer is created with showAllowed=true and showNolog=true
- **AND** Logger contains entries of all result types including nolog matches
- **THEN** output contains all entries

### Requirement: Real-time streaming to output

The Writer SHALL subscribe to the Logger and write entries as they arrive via the pub/sub notification system. Each entry SHALL be written immediately on notification (not batched). On context cancellation, the Writer SHALL perform a final drain of any unwritten entries before returning.

#### Scenario: Entries written as they arrive

- **WHEN** Writer is running
- **AND** a new entry is logged
- **THEN** the entry appears in the output before the next entry is logged

#### Scenario: Final drain on shutdown

- **WHEN** Writer's context is cancelled
- **AND** Logger contains entries that were logged after the last notification
- **THEN** those entries appear in the output before Run() returns
