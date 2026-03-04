# Monitoring Access — Observing what sandboxed commands access

## Purpose

The user enables monitoring to see what resources a sandboxed command accesses. The access log records filesystem reads/writes and network requests with their outcomes, helping the user understand and audit the command's behavior.

## Use Cases

### Use Case: View access log in text output

The user runs monitor mode to view access log entries in text format on stderr or in a file, with operation type, target, result, and matched rule columns. Filesystem target paths are displayed in shortened form. By default, only DENY and UNKNOWN entries are shown; the user can include OK entries with `--show-allowed`.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave monitor -- ls /usr/lib`
- **THEN** the access log is printed to stderr after the process exits
- **AND** by default only `DENY` and `UNKNOWN` entries are shown
- **AND** with `--show-allowed`, all entries including `OK` are shown
- **AND** paths under the config directory are shortened to relative form (e.g., `src/main.go` instead of `/home/user/project/src/main.go`)
- **AND** paths under the home directory but outside the config directory are shortened with `~` (e.g., `~/.ssh/id_rsa` instead of `/home/user/.ssh/id_rsa`)
- **AND** paths outside the home directory are shown as absolute (e.g., `/usr/lib/libc.so`)
- **AND** rules are shown verbatim as written in the config (e.g., `fs:rw:~/project`)

### Use Case: Real-time streaming to file

The user writes the access log to a file and tails it in real time as the monitored command runs.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **WHEN** the user runs `execave monitor --output-path access.log -- long-running-command`
- **AND** runs `tail -f access.log` in another terminal
- **THEN** new log entries appear in the tail output while the command is still running

### Use Case: Monitor network access (HTTPS and HTTP)

The user enables monitoring with net rules to see which network endpoints the sandboxed command contacts and whether requests are allowed or denied. Both plain HTTP and CONNECT-tunneled (HTTPS) requests appear as `HTTP` operations.

- **GIVEN** a config with rules `net:http:api.example.com:443` and `net:http:internal.example.com:3000`
- **WHEN** the user runs `execave --monitor --show-allowed -- curl https://api.example.com/data`
- **THEN** the text log displays an entry with operation `HTTP`, target `api.example.com:443`, result `OK`, rule `net:http:api.example.com:443`
- **AND** a denied request would appear with operation `HTTP`, target `evil.com:443`, result `DENY`, rule `no-matching-rule`

### Use Case: Monitor both filesystem and network concurrently

The user enables monitoring with both filesystem and network rules. The text log displays both filesystem operations and network requests.

- **GIVEN** a config with rules `fs:ro:/usr/lib`, `fs:rw:/home/user/project`, and `net:http:api.example.com:443`
- **WHEN** the user runs `execave --monitor --show-allowed -- python script.py` (where the script reads files and makes HTTPS requests)
- **THEN** the text log displays both `READ`/`WRITE` entries for filesystem paths and `HTTP` entries for network requests

### Use Case: Monitor without net rules (deny-all network logging)

The user enables monitoring without any net rules. The proxy-tunnel path starts with an empty allowlist so that network access attempts by proxy-aware programs are logged even though all are denied.

- **GIVEN** a config with only filesystem rules (no `net:` rules)
- **WHEN** the user runs `execave --monitor -- curl http://example.com`
- **THEN** the request is denied
- **AND** the text log displays an entry with operation `HTTP`, target `example.com:80`, result `DENY`, rule `no-matching-rule`

### Use Case: Access log after SIGINT

The user interrupts a long-running sandboxed command with Ctrl-C. The text log contains entries for all operations that occurred before the signal.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **WHEN** the user runs `execave --monitor=access.log -- long-running-command`
- **AND** sends SIGINT (Ctrl-C) while the command is running
- **THEN** SIGINT is forwarded to the sandboxed process
- **AND** `access.log` contains entries for filesystem operations that occurred before the signal
- **AND** execave exits with the command's exit code

### Use Case: Log deduplication (repeated accesses)

The user runs a command that accesses the same resource multiple times. Each unique `(operation, target)` pair appears in the text log only once, keeping the log concise.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **WHEN** the user runs `execave --monitor --show-allowed -- cat /home/user/data/file.txt /home/user/data/file.txt`
- **THEN** the text log displays exactly one `READ` entry for `/home/user/data/file.txt`
- **AND** if the command both reads and writes a path, both `READ` and `WRITE` entries appear (they are distinct pairs)

### Use Case: Symlink resolution hops logged

The user accesses a file through a symlink inside a mounted directory. The monitor logs each resolution hop separately, giving visibility into the full resolution chain.

- **GIVEN** a config with rule `fs:ro:/home/user/project`
- **AND** `/home/user/project/link.txt` is a symlink to `/home/user/project/real.txt`
- **WHEN** the user runs `execave --monitor --show-allowed -- cat /home/user/project/link.txt`
- **THEN** the text log displays a `READ` entry for `/home/user/project/link.txt` (the symlink hop)
- **AND** a `READ` entry for `/home/user/project/real.txt` (the resolved target)

### Use Case: Verify filesystem enforcement decisions are accurately logged

The user wants to confirm that allowed operations show OK and denied operations show DENY in the monitor, matching actual sandbox behavior. Target paths are displayed in shortened form.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:~/project/allowed.txt` and `fs:none:~/project/denied.txt`
- **WHEN** the user attempts to access both files with `execave --monitor --show-allowed -- sh -c "cat allowed.txt || true; cat denied.txt || true"`
- **THEN** the allowed file shows `READ allowed.txt OK fs:ro:~/project/allowed.txt`
- **AND** the denied file shows `READ denied.txt DENY fs:none:~/project/denied.txt`

### Use Case: Verify network enforcement decisions are accurately logged

The user wants to confirm that allowed network requests show OK and denied requests show DENY in the monitor, matching actual proxy behavior.

- **GIVEN** rules allowing one endpoint and denying another (`net:http:api.example.com:8080` and `net:none:evil.example.com:8080`)
- **WHEN** the user attempts to reach both endpoints with `execave --monitor --show-allowed -- sh -c "curl http://api.example.com:8080/ || true; curl http://evil.example.com:8080/ || true"`
- **THEN** the allowed request shows `HTTP api.example.com:8080 OK net:http:api.example.com:8080`
- **AND** the denied request shows `HTTP evil.example.com:8080 DENY net:none:evil.example.com:8080`

### Use Case: Monitor reflects filesystem rule precedence correctly

The user has nested rules (parent and more-specific child). The monitor should show which rule actually applied when multiple rules could match.

- **GIVEN** rules `fs:rw:/home/user/project` and `fs:ro:/home/user/project/.git` (child overrides parent)
- **WHEN** the user accesses files in both directories with `execave --monitor --show-allowed -- sh -c "echo test >> project/main.go && cat project/.git/config && echo fail >> project/.git/config || true"`
- **THEN** write operations in `/home/user/project/main.go` show `WRITE ... OK fs:rw:/home/user/project`
- **AND** read operations in `/home/user/project/.git/config` show `READ ... OK fs:ro:/home/user/project/.git`
- **AND** write operations in `/home/user/project/.git/config` show `WRITE ... DENY fs:ro:/home/user/project/.git` (not the parent rule)

### Use Case: Monitor reflects network rule precedence correctly

The user has overlapping network rules at different specificities. The monitor should show which rule actually applied when multiple rules could match.

- **GIVEN** rules `net:http:10.0.0.0/8:*` (broad CIDR allow) and `net:none:10.0.0.1/32:3000` (specific IP deny)
- **WHEN** the user makes requests to both a non-blocked and the blocked endpoint with `execave --monitor --show-allowed -- sh -c "curl http://10.0.0.2:3000/ || true; curl http://10.0.0.1:3000/ || true"`
- **THEN** the allowed request shows `HTTP 10.0.0.2:3000 OK net:http:10.0.0.0/8:*`
- **AND** the denied request shows `HTTP 10.0.0.1:3000 DENY net:none:10.0.0.1/32:3000` (the more specific rule, not the broad CIDR)

### Use Case: Bare-path relative accesses resolved in access log

The user runs a command that uses bare-path syscalls with relative paths (e.g., `access(".git/config")`). The monitor resolves these to absolute paths using tracked per-pid cwd, so the access log shows proper rule matching instead of UNKNOWN.

- **GIVEN** a config with rule `fs:ro:/home/user/project`
- **AND** the sandboxed command uses bare-path syscalls with relative paths (e.g., `git status` in a non-worktree repo calls `access(".git/config", R_OK)`)
- **WHEN** the user runs `execave --monitor --show-allowed -- git status`
- **THEN** the text log displays resolved absolute paths (e.g., `READ /home/user/project/.git/config OK fs:ro:/home/user/project`) instead of `UNKNOWN .git/config`

### Use Case: Unresolved relative path when no cwd tracked

The user runs a command where a bare-path relative syscall occurs before any cwd can be tracked for that pid. The monitor falls back to logging the relative path as UNKNOWN.

- **GIVEN** a config with filesystem rules
- **AND** the sandboxed command emits a bare-path relative syscall before any AT_FDCWD-annotated call from the same pid
- **WHEN** the user runs `execave --monitor -- <command>`
- **THEN** the text log displays the unresolved relative path with result `UNKNOWN` and rule `unresolved-relative-path`

### Use Case: Default view shows only denied and unknown entries

The user runs with `--monitor` and sees only DENY and UNKNOWN entries by default. OK entries are omitted unless `--show-allowed` is used.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/home/user/project`
- **WHEN** the user runs `execave --monitor -- ls /usr/lib /home/user/project`
- **THEN** the text log displays only `DENY` and `UNKNOWN` entries
- **AND** `OK` entries for reads under `/usr/lib` and `/home/user/project` are not shown

### Use Case: Toggle to show all entries

The user uses `--show-allowed` to include OK entries in the text log.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/home/user/project`
- **WHEN** the user runs `execave --monitor --show-allowed -- ls /usr/lib`
- **THEN** the text log displays all entries including `OK` entries for reads under `/usr/lib`

### Use Case: Write access log to file

The user writes the access log to a file, useful when TUI apps cover the terminal.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave --monitor=access.log -- vim src/main.go`
- **AND** the sandboxed command accesses files
- **THEN** `access.log` is created in the current directory
- **AND** entries are written to the file as they occur (tailable with `tail -f access.log`)
- **AND** each line contains result, operation, target path (shortened), and matched rule
- **AND** by default only DENY and UNKNOWN entries are written (OK entries are hidden)
- **AND** filesystem paths are shortened (relative to config dir, or `~/` form)

### Use Case: Write access log to stderr after process exits

The user writes the access log to stderr, which is buffered until the sandboxed process exits to avoid interleaving with the command's output.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave --monitor -- ls /usr/lib`
- **AND** the sandboxed command exits
- **THEN** the accumulated access log entries are printed to stderr after the process exits
- **AND** by default only DENY and UNKNOWN entries are shown

### Use Case: Show allowed entries in text log

The user includes OK entries in the text log output using the `--show-allowed` flag.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave --monitor=access.log --show-allowed -- ls /usr/lib`
- **THEN** `access.log` contains both OK and DENY/UNKNOWN entries

### Use Case: Text log survives SIGINT

The user interrupts a long-running command and the text log contains all entries logged before the signal.

- **GIVEN** a config with rules `fs:ro:/home/user/data`
- **WHEN** the user runs `execave --monitor=access.log -- long-running-command`
- **AND** sends SIGINT (Ctrl-C) while the command is running
- **THEN** `access.log` contains entries for all operations that occurred before the signal
- **AND** execave exits with the command's exit code

### Use Case: Observe native filesystem accesses to diagnose sandbox failures

The user runs a command with `--no-sandbox --monitor` to observe all filesystem accesses the program makes on the real host filesystem, without bwrap isolation. This is useful for diagnosing why a program fails inside the sandbox — the access log shows every path the program probes, including ancestor directories or fallback paths that might be missing in the sandboxed view.

- **GIVEN** a config with filesystem rules (e.g., `fs:ro:/usr/lib`, `fs:rw:~/project`)
- **WHEN** the user runs `execave --no-sandbox --monitor -- myapp`
- **THEN** `myapp` runs natively on the host filesystem (no bwrap, no filesystem isolation)
- **AND** the access log is printed to stderr after the process exits (same as `--monitor` without `--no-sandbox`)
- **AND** log entries show all filesystem accesses with result `UNENFORCED`, making it immediately clear that no sandboxing was active
- **AND** the user can see accesses to ancestor directories, fallback library paths, and other paths that are not present in the sandboxed view

### Use Case: Write native access log to file in real time

The user runs with `--no-sandbox --monitor=<path>` to stream the native access log to a file while the program runs, useful for long-running programs.

- **GIVEN** a config with filesystem rules
- **WHEN** the user runs `execave --no-sandbox --monitor=native.log -- myapp`
- **AND** runs `tail -f native.log` in another terminal
- **THEN** `myapp` runs natively on the host filesystem
- **AND** new log entries appear in the tail output while the command is still running

### Use Case: Observe native network accesses without isolation

The user runs with `--no-sandbox --monitor` and the config has net rules. The network proxy starts and HTTP_PROXY/HTTPS_PROXY are set, so proxy-aware HTTP traffic goes through the proxy and is logged against net rules, but there is no network namespace isolation. Connections are never blocked — rules are evaluated for logging only.

- **GIVEN** a config with no net rules (empty rules)
- **WHEN** the user runs `execave --no-sandbox --monitor --show-allowed -- curl http://<local-server>/`
- **THEN** `curl` is proxy-aware and sends its request through the proxy (HTTP_PROXY is set)
- **AND** the request reaches the server and succeeds (not blocked with 403 despite no matching rule)
- **AND** the text log displays an entry with operation `HTTP`, target `<local-server>`, result `UNENFORCED`
- **AND** the host network interfaces remain accessible (no `--unshare-net`)

### Use Case: Error when --no-sandbox is used without --monitor

The user attempts to run with `--no-sandbox` but forgets to specify `--monitor`. execave exits with a clear error message.

- **GIVEN** a valid config
- **WHEN** the user runs `execave --no-sandbox -- myapp` (without `--monitor`)
- **THEN** execave exits with an error message indicating that `--monitor` is required when `--no-sandbox` is used
- **AND** `myapp` is not executed

### Use Case: Monitor-specific flags are scoped to monitor command
The user uses monitor-only behavior through the `monitor` subcommand, while root flags remain global.

- **GIVEN** a valid config file
- **WHEN** the user runs `execave --config ./execave.toml monitor --show-allowed --no-sandbox --output-path monitor.log -- command`
- **THEN** monitor mode runs with those flags applied
- **AND** `--config` is accepted before the subcommand as a global option
