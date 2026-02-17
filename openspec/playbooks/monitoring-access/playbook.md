# Monitoring Access — Observing what sandboxed commands access

## Purpose

The user enables monitoring to see what resources a sandboxed command accesses. The access log records filesystem reads/writes and network requests with their outcomes, helping the user understand and audit the command's behavior.

## Use Cases

### Use Case: View access log in web UI

The user opens the web UI in a browser to view access log entries in a structured table with operation type, target, result, and matched rule columns. Filesystem target paths are displayed in shortened form: relative to config directory when possible, or with `~/` prefix, whichever is shorter.

- **GIVEN** a config at `/home/user/project/execave.toml` with rules `fs:ro:/usr/lib` and `fs:rw:~/project`
- **WHEN** the user runs `execave --monitor=9876 -- ls /usr/lib`
- **THEN** `execave: monitor at http://127.0.0.1:9876` is printed to stderr
- **AND** opening `http://127.0.0.1:9876` in a browser displays a table with `READ` entries
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

The user enables monitoring with net rules to see which network endpoints the sandboxed command contacts and whether requests are allowed or denied.

- **GIVEN** a config with rules `net:https:api.example.com:443` and `net:http:internal.example.com:3000`
- **WHEN** the user runs `execave --monitor=9876 -- curl https://api.example.com/data`
- **THEN** the web UI displays an entry with operation `HTTPS`, target `api.example.com:443`, result `OK`, rule `net:https:api.example.com:443`
- **AND** a denied request would appear with operation `HTTPS`, target `evil.com:443`, result `DENY`, rule `no-matching-rule`

### Use Case: Monitor both filesystem and network concurrently

The user enables monitoring with both filesystem and network rules. The web UI displays both filesystem operations and network requests.

- **GIVEN** a config with rules `fs:ro:/usr/lib`, `fs:rw:/home/user/project`, and `net:https:api.example.com:443`
- **WHEN** the user runs `execave --monitor=9876 -- python script.py` (where the script reads files and makes HTTPS requests)
- **THEN** the web UI displays both `READ`/`WRITE` entries for filesystem paths and `HTTPS` entries for network requests

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
