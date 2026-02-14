# Monitoring Access — Observing what sandboxed commands access

## Purpose

The user enables monitoring to see what resources a sandboxed command accesses. The access log records filesystem reads/writes and network requests with their outcomes, helping the user understand and audit the command's behavior.

## Use Cases

### Use Case: Monitor filesystem access with default log path

The user enables monitoring to see which files the sandboxed command reads and writes. The access log is written to the default location.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/home/user/project`
- **WHEN** the user runs `execave --monitor -- ls /usr/lib`
- **THEN** the command succeeds
- **AND** an access log is written to `./execave-access.log`
- **AND** the log contains `READ` entries for filesystem paths the command accessed

### Use Case: Monitor filesystem access with custom log path

The user specifies a custom log path to control where the access log is written.

- **GIVEN** a config with rule `fs:ro:/usr/bin`
- **WHEN** the user runs `execave --monitor=/tmp/my-access.log -- ls /usr/bin`
- **THEN** the command succeeds
- **AND** the access log is written to `/tmp/my-access.log` instead of the default location

### Use Case: Monitor network access (HTTPS and HTTP)

The user enables monitoring with net rules to see which network endpoints the sandboxed command contacts and whether requests are allowed or denied.

- **GIVEN** a config with rules `net:https:api.example.com:443` and `net:http:internal.example.com:3000`
- **WHEN** the user runs `execave --monitor -- curl https://api.example.com/data`
- **THEN** the log contains `HTTPS api.example.com:443 OK net:https:api.example.com:443`
- **AND** a denied request would appear as `HTTPS evil.com:443 DENY no-matching-rule`

### Use Case: Monitor both filesystem and network concurrently

The user enables monitoring with both filesystem and network rules. The access log captures both filesystem operations and network requests in a single file.

- **GIVEN** a config with rules `fs:ro:/usr/lib`, `fs:rw:/home/user/project`, and `net:https:api.example.com:443`
- **WHEN** the user runs `execave --monitor -- python script.py` (where the script reads files and makes HTTPS requests)
- **THEN** the log contains both `READ`/`WRITE` entries for filesystem paths and `HTTPS` entries for network requests

### Use Case: Real-time log monitoring (tail -f during execution)

The user watches the access log in real time while the sandboxed command runs. Log entries appear as syscalls are processed, not after the command exits.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **WHEN** the user runs `execave --monitor -- long-running-command` in one terminal
- **AND** runs `tail -f ./execave-access.log` in another terminal
- **THEN** log entries appear in the second terminal while the command is still running

### Use Case: Monitor without net rules (deny-all network logging)

The user enables monitoring without any net rules. The proxy-tunnel path starts with an empty allowlist so that network access attempts by proxy-aware programs are logged even though all are denied.

- **GIVEN** a config with only filesystem rules (no `net:` rules)
- **WHEN** the user runs `execave --monitor -- curl http://example.com`
- **THEN** the request is denied
- **AND** the log contains `HTTP example.com:80 DENY no-matching-rule`

### Use Case: Access log after SIGINT

The user interrupts a long-running sandboxed command with Ctrl-C. The access log contains entries for all operations that occurred before the signal.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **WHEN** the user runs `execave --monitor -- long-running-command`
- **AND** sends SIGINT (Ctrl-C) while the command is running
- **THEN** the access log contains entries for filesystem operations that occurred before the signal
- **AND** execave exits with the child's exit code (130 for SIGINT)

### Use Case: Log deduplication (repeated accesses)

The user runs a command that accesses the same resource multiple times. Each unique `(operation, target)` pair appears in the log only once, keeping the log concise.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **WHEN** the user runs `execave --monitor -- cat /home/user/data/file.txt /home/user/data/file.txt`
- **THEN** the log contains exactly one `READ` entry for `/home/user/data/file.txt`
- **AND** if the command both reads and writes a path, both `READ` and `WRITE` entries appear (they are distinct pairs)

### Use Case: Symlink resolution hops logged

The user accesses a file through a symlink inside a mounted directory. The monitor logs each resolution hop separately, giving visibility into the full resolution chain.

- **GIVEN** a config with rule `fs:ro:/home/user/project`
- **AND** `/home/user/project/link.txt` is a symlink to `/home/user/project/real.txt`
- **WHEN** the user runs `execave --monitor -- cat /home/user/project/link.txt`
- **THEN** the log contains a `READ` entry for `/home/user/project/link.txt` (the symlink hop)
- **AND** a `READ` entry for `/home/user/project/real.txt` (the resolved target)
