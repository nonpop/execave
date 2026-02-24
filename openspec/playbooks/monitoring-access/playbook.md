# Monitoring Access — Observing what sandboxed commands access

## Purpose

The user enables monitoring to see what resources a sandboxed command accesses. The access log records filesystem reads/writes and network requests with their outcomes, helping the user understand and audit the command's behavior.

## Use Cases

### Use Case: View access log in web UI

The user opens the web UI in a browser to view access log entries in a structured table with operation type, target, result, and matched rule columns. Filesystem target paths are displayed in shortened form: relative to config directory when possible, or with `~/` prefix, whichever is shorter. By default, only DENY and UNKNOWN entries are shown; the user can toggle to show all entries.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/lib`
- **THEN** `execave: monitor at http://127.0.0.1:9876` is printed to stderr
- **AND** opening `http://127.0.0.1:9876` in a browser displays a table with only `DENY` and `UNKNOWN` entries by default
- **AND** a "Denied only" checkbox is checked by default; unchecking it reveals all entries including `OK`
- **AND** paths under the config directory are shortened to relative form (e.g., `src/main.go` instead of `/home/user/project/src/main.go`)
- **AND** paths under the home directory but outside the config directory are shortened with `~` (e.g., `~/.ssh/id_rsa` instead of `/home/user/.ssh/id_rsa`)
- **AND** paths outside the home directory are shown as absolute (e.g., `/usr/lib/libc.so`)
- **AND** rules are shown verbatim as written in the config (e.g., `fs:rw:~/project`)

### Use Case: Real-time streaming via web UI

The user watches access log entries appear in the browser in real time as the sandboxed command runs.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **WHEN** the user runs `execave --monitor=9876 -- long-running-command`
- **AND** opens `http://127.0.0.1:9876` in a browser
- **THEN** new log entries appear in the table while the command is still running, without page refresh

### Use Case: Web UI survives sandbox exit

The user can review access log entries in the web UI after the sandboxed command has exited.

- **GIVEN** a config with rule `fs:ro:/usr/bin`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/bin`
- **AND** the command exits
- **THEN** execave prints a message to stderr indicating the process exited and Ctrl-C will stop the monitor
- **AND** the web UI remains accessible at `http://127.0.0.1:9876`
- **AND** the user can still view all logged entries

### Use Case: SIGINT after sandbox exit stops web UI

The user presses Ctrl-C after the sandboxed command has exited to stop the web UI server.

- **GIVEN** a config with rule `fs:ro:/usr/bin`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/bin`
- **AND** the command exits
- **AND** the user sends SIGINT (Ctrl-C)
- **THEN** execave exits immediately

### Use Case: Run status shown in web UI

The user sees the sandboxed command and its execution status (running or exited with exit code) in the web UI.

- **GIVEN** a config with rule `fs:ro:/usr/bin`
- **WHEN** the user runs `execave --monitor=9876 -- echo hello`
- **AND** opens the web UI page
- **THEN** the page displays the command `echo hello`
- **AND** the page displays whether the process is running or has exited (with exit code)

### Use Case: No entries lost on page refresh

The user refreshes the web UI page and sees all entries accumulated so far, with no gaps when SSE streaming resumes.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **WHEN** the user runs `execave --monitor=9876 -- long-running-command`
- **AND** opens the web UI and sees entries accumulating
- **AND** refreshes the page
- **THEN** the page displays all entries accumulated so far
- **AND** new entries continue appearing without duplicates or gaps

### Use Case: Monitor network access (HTTPS and HTTP)

The user enables monitoring with net rules to see which network endpoints the sandboxed command contacts and whether requests are allowed or denied. Both plain HTTP and CONNECT-tunneled (HTTPS) requests appear as `HTTP` operations.

- **GIVEN** a config with rules `net:http:api.example.com:443` and `net:http:internal.example.com:3000`
- **WHEN** the user runs `execave --monitor=9876 -- curl https://api.example.com/data`
- **THEN** the web UI displays an entry with operation `HTTP`, target `api.example.com:443`, result `OK`, rule `net:http:api.example.com:443`
- **AND** a denied request would appear with operation `HTTP`, target `evil.com:443`, result `DENY`, rule `no-matching-rule`

### Use Case: Monitor both filesystem and network concurrently

The user enables monitoring with both filesystem and network rules. The web UI displays both filesystem operations and network requests.

- **GIVEN** a config with rules `fs:ro:/usr/lib`, `fs:rw:/home/user/project`, and `net:http:api.example.com:443`
- **WHEN** the user runs `execave --monitor=9876 -- python script.py` (where the script reads files and makes HTTPS requests)
- **THEN** the web UI displays both `READ`/`WRITE` entries for filesystem paths and `HTTP` entries for network requests

### Use Case: Monitor without net rules (deny-all network logging)

The user enables monitoring without any net rules. The proxy-tunnel path starts with an empty allowlist so that network access attempts by proxy-aware programs are logged even though all are denied.

- **GIVEN** a config with only filesystem rules (no `net:` rules)
- **WHEN** the user runs `execave --monitor=9876 -- curl http://example.com`
- **THEN** the request is denied
- **AND** the web UI displays an entry with operation `HTTP`, target `example.com:80`, result `DENY`, rule `no-matching-rule`

### Use Case: Access log after SIGINT

The user interrupts a long-running sandboxed command with Ctrl-C. The web UI contains entries for all operations that occurred before the signal, and the server remains running.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **WHEN** the user runs `execave --monitor=9876 -- long-running-command`
- **AND** sends SIGINT (Ctrl-C) while the command is running
- **THEN** SIGINT is forwarded to the sandboxed process
- **AND** the web UI contains entries for filesystem operations that occurred before the signal
- **AND** the web UI server remains running after the sandbox exits

### Use Case: Log deduplication (repeated accesses)

The user runs a command that accesses the same resource multiple times. Each unique `(operation, target)` pair appears in the web UI only once, keeping the log concise.

- **GIVEN** a config with rule `fs:ro:/home/user/data`
- **WHEN** the user runs `execave --monitor=9876 -- cat /home/user/data/file.txt /home/user/data/file.txt`
- **THEN** the web UI displays exactly one `READ` entry for `/home/user/data/file.txt`
- **AND** if the command both reads and writes a path, both `READ` and `WRITE` entries appear (they are distinct pairs)

### Use Case: Symlink resolution hops logged

The user accesses a file through a symlink inside a mounted directory. The monitor logs each resolution hop separately, giving visibility into the full resolution chain.

- **GIVEN** a config with rule `fs:ro:/home/user/project`
- **AND** `/home/user/project/link.txt` is a symlink to `/home/user/project/real.txt`
- **WHEN** the user runs `execave --monitor=9876 -- cat /home/user/project/link.txt`
- **THEN** the web UI displays a `READ` entry for `/home/user/project/link.txt` (the symlink hop)
- **AND** a `READ` entry for `/home/user/project/real.txt` (the resolved target)

### Use Case: Verify filesystem enforcement decisions are accurately logged

The user wants to confirm that allowed operations show OK and denied operations show DENY in the monitor, matching actual sandbox behavior. Target paths are displayed in shortened form.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:~/project/allowed.txt` and `fs:none:~/project/denied.txt`
- **WHEN** the user attempts to access both files with `execave --monitor -- sh -c "cat allowed.txt || true; cat denied.txt || true"`
- **THEN** the allowed file shows `READ allowed.txt OK fs:ro:~/project/allowed.txt`
- **AND** the denied file shows `READ denied.txt DENY fs:none:~/project/denied.txt`

### Use Case: Verify network enforcement decisions are accurately logged

The user wants to confirm that allowed network requests show OK and denied requests show DENY in the monitor, matching actual proxy behavior.

- **GIVEN** rules allowing one endpoint and denying another (`net:http:api.example.com:8080` and `net:none:evil.example.com:8080`)
- **WHEN** the user attempts to reach both endpoints with `execave --monitor -- sh -c "curl http://api.example.com:8080/ || true; curl http://evil.example.com:8080/ || true"`
- **THEN** the allowed request shows `HTTP api.example.com:8080 OK net:http:api.example.com:8080`
- **AND** the denied request shows `HTTP evil.example.com:8080 DENY net:none:evil.example.com:8080`

### Use Case: Monitor reflects filesystem rule precedence correctly

The user has nested rules (parent and more-specific child). The monitor should show which rule actually applied when multiple rules could match.

- **GIVEN** rules `fs:rw:/home/user/project` and `fs:ro:/home/user/project/.git` (child overrides parent)
- **WHEN** the user accesses files in both directories with `execave --monitor -- sh -c "echo test >> project/main.go && cat project/.git/config && echo fail >> project/.git/config || true"`
- **THEN** write operations in `/home/user/project/main.go` show `WRITE ... OK fs:rw:/home/user/project`
- **AND** read operations in `/home/user/project/.git/config` show `READ ... OK fs:ro:/home/user/project/.git`
- **AND** write operations in `/home/user/project/.git/config` show `WRITE ... DENY fs:ro:/home/user/project/.git` (not the parent rule)

### Use Case: Monitor reflects network rule precedence correctly

The user has overlapping network rules at different specificities. The monitor should show which rule actually applied when multiple rules could match.

- **GIVEN** rules `net:http:10.0.0.0/8:*` (broad CIDR allow) and `net:none:10.0.0.1/32:3000` (specific IP deny)
- **WHEN** the user makes requests to both a non-blocked and the blocked endpoint with `execave --monitor -- sh -c "curl http://10.0.0.2:3000/ || true; curl http://10.0.0.1:3000/ || true"`
- **THEN** the allowed request shows `HTTP 10.0.0.2:3000 OK net:http:10.0.0.0/8:*`
- **AND** the denied request shows `HTTP 10.0.0.1:3000 DENY net:none:10.0.0.1/32:3000` (the more specific rule, not the broad CIDR)

### Use Case: Bare-path relative accesses resolved in access log

The user runs a command that uses bare-path syscalls with relative paths (e.g., `access(".git/config")`). The monitor resolves these to absolute paths using tracked per-pid cwd, so the access log shows proper rule matching instead of UNKNOWN.

- **GIVEN** a config with rule `fs:ro:/home/user/project`
- **AND** the sandboxed command uses bare-path syscalls with relative paths (e.g., `git status` in a non-worktree repo calls `access(".git/config", R_OK)`)
- **WHEN** the user runs `execave --monitor=9876 -- git status`
- **THEN** the web UI displays resolved absolute paths (e.g., `READ /home/user/project/.git/config OK fs:ro:/home/user/project`) instead of `UNKNOWN .git/config`

### Use Case: Unresolved relative path when no cwd tracked

The user runs a command where a bare-path relative syscall occurs before any cwd can be tracked for that pid. The monitor falls back to logging the relative path as UNKNOWN.

- **GIVEN** a config with filesystem rules
- **AND** the sandboxed command emits a bare-path relative syscall before any AT_FDCWD-annotated call from the same pid
- **WHEN** the user runs `execave --monitor=9876 -- <command>`
- **THEN** the web UI displays the unresolved relative path with result `UNKNOWN` and rule `unresolved-relative-path`

### Use Case: Default view shows only denied and unknown entries

The user opens the web UI and sees only DENY and UNKNOWN entries by default. OK entries are hidden until the user opts in.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/home/user/project`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/lib /home/user/project`
- **THEN** the web UI displays only `DENY` and `UNKNOWN` entries
- **AND** `OK` entries for reads under `/usr/lib` and `/home/user/project` are not shown
- **AND** a "Denied only" checkbox is checked by default

### Use Case: Toggle to show all entries

The user unchecks the "denied only" toggle to see all entries including allowed accesses.

- **GIVEN** a config with rules `fs:ro:/usr/lib` and `fs:rw:/home/user/project`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/lib`
- **AND** opens the web UI and unchecks the "Denied only" checkbox
- **THEN** the web UI displays all entries including `OK` entries for reads under `/usr/lib`

### Use Case: Suppress expected denies with fs:nolog

The user adds an `fs:nolog` rule to suppress known harmless deny entries from a path.

- **GIVEN** a config with rules `fs:ro:/home/user/project` and `fs:nolog:/home/user/project/cache`
- **AND** the sandboxed app always tries to write to `/home/user/project/cache/data` on startup (which is denied by the ro rule, but the app tolerates the failure)
- **WHEN** the user runs `execave --monitor=9876 -- myapp`
- **THEN** the web UI does not display the `WRITE /home/user/project/cache/data DENY` entry
- **AND** other entries under `/home/user/project` are still displayed

### Use Case: Override nolog with fs:log for a subtree

The user nologs a broad directory but overrides with `fs:log` for a specific child path they still want to monitor.

- **GIVEN** a config with rules `fs:ro:/home/user/project`, `fs:nolog:/home/user/project`, and `fs:log:/home/user/project/secret`
- **WHEN** the user runs `execave --monitor=9876 -- sh -c "cat /home/user/project/data.txt; cat /home/user/project/secret/key.pem"`
- **THEN** the web UI does not display entries for `/home/user/project/data.txt` (suppressed by nolog)
- **AND** the web UI displays entries for `/home/user/project/secret/key.pem` (overridden by the more specific log rule)

### Use Case: Suppress expected network denies with net:nolog

The user adds a `net:nolog` rule to suppress known harmless network deny entries.

- **GIVEN** a config with rules `net:http:api.example.com:443` and `net:nolog:telemetry.example.com:443`
- **AND** the sandboxed app always tries to reach `telemetry.example.com:443` on startup (denied, but the app continues fine)
- **WHEN** the user runs `execave --monitor=9876 -- myapp`
- **THEN** the web UI does not display the `HTTP telemetry.example.com:443 DENY` entry
- **AND** other network entries are still displayed

### Use Case: Override net:nolog with net:log for specific endpoint

The user nologs a wildcard domain but overrides with `net:log` for a specific subdomain.

- **GIVEN** a config with rules `net:http:*.example.com:443`, `net:nolog:*.example.com:443`, and `net:log:api.example.com:443`
- **WHEN** the user runs `execave --monitor=9876 -- sh -c "curl https://cdn.example.com/ || true; curl https://api.example.com/ || true"`
- **THEN** the web UI does not display entries for `cdn.example.com:443` (suppressed by nolog)
- **AND** the web UI displays entries for `api.example.com:443` (overridden by the more specific log rule)

### Use Case: Toggle to show nolog-suppressed entries

The user unchecks the "apply nolog rules" toggle to temporarily see all entries including those suppressed by nolog rules.

- **GIVEN** a config with rules `fs:ro:/home/user/project` and `fs:nolog:/home/user/project`
- **WHEN** the user runs `execave --monitor=9876 -- ls /home/user/project`
- **AND** opens the web UI and unchecks the "Apply nolog rules" checkbox
- **THEN** the web UI displays all entries for `/home/user/project`, including those that were suppressed

### Use Case: Both filters are independent

Both the "denied only" toggle and "apply nolog rules" toggle operate independently. An entry must pass both filters to be displayed.

- **GIVEN** a config with rules `fs:ro:/usr/lib`, `fs:rw:/home/user/project`, and `fs:nolog:/usr/lib`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/lib /home/user/project`
- **AND** unchecks "Denied only" but leaves "Apply nolog rules" checked
- **THEN** the web UI displays OK entries for `/home/user/project` (passes both filters)
- **AND** does not display OK entries for `/usr/lib` (passes mode filter but blocked by nolog)

### Use Case: Log rule specificity matches access rule semantics for fs

Filesystem log rules use longest-prefix-match, same as access rules. The most specific log/nolog rule for a path wins.

- **GIVEN** a config with rules `fs:ro:/home/user`, `fs:nolog:/home/user`, `fs:log:/home/user/project`, and `fs:nolog:/home/user/project/vendor`
- **WHEN** the user runs `execave --monitor=9876 -- sh -c "cat /home/user/.bashrc; cat /home/user/project/main.go; cat /home/user/project/vendor/lib.go"`
- **THEN** entries for `/home/user/.bashrc` are suppressed (matches `fs:nolog:/home/user`)
- **AND** entries for `/home/user/project/main.go` are displayed (matches `fs:log:/home/user/project`)
- **AND** entries for `/home/user/project/vendor/lib.go` are suppressed (matches `fs:nolog:/home/user/project/vendor`)

### Use Case: Log rule specificity matches access rule semantics for net

Network log rules use the same specificity ranking as access rules. Exact domain beats wildcard; longer CIDR prefix beats shorter.

- **GIVEN** a config with rules `net:http:*.example.com:443`, `net:nolog:*.example.com:443`, and `net:log:api.example.com:443`
- **WHEN** the user runs `execave --monitor=9876 -- sh -c "curl https://cdn.example.com/ || true; curl https://api.example.com/ || true"`
- **THEN** entries for `cdn.example.com:443` are suppressed (matches wildcard nolog)
- **AND** entries for `api.example.com:443` are displayed (exact match log overrides wildcard nolog)
