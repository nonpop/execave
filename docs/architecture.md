# Architecture

Execave is a process, filesystem, and network sandboxing CLI. It wraps commands in a bubblewrap (`bwrap`) sandbox that starts empty (default-deny) and only exposes paths and network targets explicitly allowed in the config.

```mermaid
flowchart TB
    subgraph Trusted["TRUSTED (host)"]
        CLI[CLI: cmd/execave]
        Config[Config: internal/config]
        FSRules[FS Rules: internal/fsrules]
        NetRules[Net Rules: internal/netrules]
        AccessLog[Access Log: internal/accesslog]
        Sandbox[Sandbox: internal/sandbox]
        Monitor[Monitor: internal/monitor]
        Proxy[Proxy: internal/proxy]
        WebUI[Web UI: internal/webui]
    end

    subgraph Untrusted["UNTRUSTED (sandboxed)"]
        Tunnel[Tunnel: internal/tunnel]
        Process[Sandboxed Process]
    end

    subgraph Browser["Browser"]
        Page[HTML Page]
        SSE[SSE Client]
    end

    CLI --> Config
    CLI --> Sandbox
    CLI --> Monitor
    CLI --> Proxy
    CLI --> WebUI
    Config --> FSRules
    Config --> NetRules
    Monitor --> FSRules
    Monitor --> AccessLog
    Proxy --> NetRules
    Proxy --> AccessLog
    WebUI --> AccessLog
    Sandbox --> FSRules
    Sandbox -->|bwrap| Tunnel
    Tunnel --> Process
    Tunnel -->|UDS| Proxy
    Monitor -->|strace + bwrap| Tunnel
    WebUI -->|HTTP| Page
    WebUI -->|SSE| SSE
```

## Components

### Config (`internal/config/`)

- Loads JSON configuration and routes rules by resource prefix
- Routes `fs:` rules to `fsrules.Parse()` and `net:` rules to `netrules.Parse()`
- Rejects unknown resource prefixes (not `fs:` or `net:`)
- Calls each rule package's cross-rule validation after parsing
- Thin layer focused on JSON parsing and rule routing

### FS Rules (`internal/fsrules/`)

Self-contained FS rule engine handling parsing, validation, and resolution.

**Parsing and validation:**
- Rule syntax: `fs:<permission>:<path>`
- Permissions: `rw`, `ro`, `none`
- Path normalization (relative → absolute)
- Cross-rule validation: no duplicates, managed paths protected, config file not writable
- Symlinks resolved at runtime, not during config parsing

**Rule resolution:**
- Most-specific path wins (longest prefix matching)
- `PermissionFor`: returns permission for a path
- `CheckAccess`: resolves symlinks and checks operation permission
- Used by both sandbox (config file protection) and monitor (access attribution)

See security-model.md for path normalization risks.

### Net Rules (`internal/netrules/`)

Self-contained net rule engine handling parsing, validation, and resolution.

**Parsing and validation:**
- Rule syntax: `net:<protocol>:<target>:<port>`
- Protocols: `https`, `http`, `none`
- Target types: domain (with optional wildcard), IPv4/IPv6, CIDR
- Parsing order: bracketed IPv6 → CIDR → IP → domain fallback
- Cross-rule validation: no duplicate `(target, port)` identity, no mixed port patterns per target

**Rule resolution:**
- Single-dimension target specificity: exact > wildcard (domains), longer prefix > shorter (CIDRs)
- Protocol compatibility: `none` matches any protocol
- Default-deny when no rule matches

### Access Log (`internal/accesslog/`)

In-memory access log storage with deduplication, filtering, and pub/sub notifications.

- Entry storage: maintains `[]Entry` slice with thread-safe access
- Deduplication: each unique (operation, target, result) logged once
- Infrastructure filtering: `/dev`, `/proc`, `/tmp`, `/newroot`, `/oldroot`
- Pub/sub mechanism: subscribers notified on new entries (non-blocking sends)
- Entry format: `Operation`, `Target`, `Result`, `Rule` fields
- Used by monitor (filesystem), proxy (network), and web UI (display)

### Web UI (`internal/webui/`)

Localhost web server for real-time access log viewing. Active when `--monitor=PORT` is specified.

- HTTP server bound to `127.0.0.1:PORT`
- Dependencies: `*accesslog.Logger` (entries), `StatusProvider` interface (run status)
- Routes:
  - `GET /` - Server-rendered HTML page with current entries and SSE client
  - `GET /events?from=N` - Server-Sent Events stream for real-time updates
- `StatusProvider` interface: read-only access to `RunStatus` (command, running/exited, etc.) with pub/sub. Concrete `statusTracker` lives in `cmd/execave` — CLI orchestrator calls `SetRunning()`/`SetExited()`; Server subscribes for changes via the interface.
- SSE cursor-based streaming: replays entries from index N, then streams new entries
- Session-aware reconnection: SSE event IDs encode `sessionID:index`; cross-session reconnects replay from 0 and the client clears stale entries
- Server lifecycle: starts before sandbox, survives sandbox exit, stops on SIGINT

### Sandbox (`internal/sandbox/`)

- Translates rules to bwrap args:
  - `fs:rw` → `--bind`
  - `fs:ro` → `--ro-bind`
  - `fs:none` → `--tmpfs` (directories) or `--bind /dev/null` (files)
- Mount ordering: shortest paths first (parents before children); children overlay parents

When net rules are configured or monitoring is enabled, the sandbox bind-mounts the proxy UDS (`/tmp/execave-proxy.sock`) and the execave binary (`/tmp/execave`) read-only, then wraps the user command with `execave network-tunnel`.

See security-model.md for bwrap arg risks.

#### Automatic vs. Explicit Mounts

**Automatic:** `/dev`, `/proc`, `/tmp` (require special bwrap args)

**Explicit (must be in config):** Everything else—`/usr`, `/lib`, `/lib64`, `/sys`, dynamic linker files, user data. See `execave.json.example`.

#### Working Directory

The sandboxed process inherits the host's working directory. If the host cwd is not mounted in the sandbox, bwrap automatically falls back to `/`.

#### Process Isolation

Uses `--unshare-all` for full namespace isolation (PID, IPC, UTS, cgroup, network). On older kernels, uses `--new-session` to prevent TIOCSTI terminal injection; on Linux 6.2+ where the kernel blocks TIOCSTI, `--new-session` is skipped to allow SIGWINCH delivery for TUI applications. Environment variables pass through from the host. Network is isolated by default; when net rules are configured or monitoring is enabled, a proxy-tunnel bridge provides controlled access (or deny-all logging with no net rules).

### Proxy (`internal/proxy/`)

Forward HTTP proxy listening on a Unix domain socket. Runs on the host (trusted side).

- Handles CONNECT for HTTPS tunneling and plain HTTP forwarding
- Checks each request against `netrules.Resolver` allowlist
- Denied requests receive 403 Forbidden
- Logs each request to `accesslog.Logger` (if monitoring enabled)
- Lifecycle: `Start()` creates UDS → `Stop()` drains connections → removes UDS

### Tunnel (`internal/tunnel/`)

TCP-to-UDS bridge running inside the sandbox (untrusted side).

- Listens on `127.0.0.1:0` inside the sandbox
- Relays TCP connections to the proxy UDS
- Sets `HTTP_PROXY`/`HTTPS_PROXY`/`http_proxy`/`https_proxy` to `http://127.0.0.1:<port>`
- Unsets `NO_PROXY`/`no_proxy` (bypass would lose connectivity, not circumvent allowlist)
- Runs user command as subprocess, propagates exit code
- Fail-closed: exits non-zero if listener bind or UDS access fails

### Monitor (`internal/monitor/`)

Optional (`--monitor=PORT`). Traces filesystem access via strace and logs with rule attribution. Displayed in real-time web UI.

- Wraps bwrap: `strace -- bwrap [args] -- cmd`
- Parses strace output, maps syscalls to operations (READ/WRITE)
- Filters setup/infrastructure syscalls (bwrap's namespace creation)
- Uses `fsrules.Resolver` for symlink resolution and rule matching
- Filters non-existent path reads (via resolver's `PathNotFound` field)
- Constructs `accesslog.Entry` for each access and delegates to `accesslog.Logger`
- Symlinks targeting managed paths logged as UNKNOWN (host can't resolve sandbox-internal filesystems)
- Entries stored in memory (not file) and streamed to web UI via SSE

## Data Flow

**Startup:** CLI parses args → loads config (routes rules to `fsrules` and `netrules`) → creates resolvers → creates access logger and status tracker (if `--monitor=PORT`) → starts web UI server with status tracker as `StatusProvider` (if `--monitor=PORT`) → starts proxy (if net rules or monitoring) → executes `bwrap` (or `strace + bwrap` with monitoring)

**Runtime (without net rules, no monitoring):** Kernel enforces namespace isolation (mount, PID, IPC, network). No network access. No proxy.

**Runtime (without net rules, monitoring enabled):** Same namespace isolation. Proxy-tunnel starts with an empty rule set (deny-all) so that HTTP-proxy-aware programs' access attempts are logged. Direct connections still fail (no NIC). Monitor traces syscalls, resolves via `fsrules`, logs via `accesslog`. Web UI serves initial page with all entries and streams updates via SSE. Browser connects to `http://127.0.0.1:PORT` to view real-time log.

**Runtime (with net rules):** Same namespace isolation. Inside the sandbox, the tunnel listens on loopback and bridges TCP to the proxy UDS. Proxy checks each request against net rules and forwards or denies. Both monitor (filesystem) and proxy (network) log to the same `accesslog`. If monitoring enabled, web UI displays both filesystem and network entries in real-time.

**Shutdown (monitoring enabled):** After sandbox exits, web UI server remains accessible for log review. SIGINT exits immediately; the OS closes all connections.

## Dependencies

- `bwrap` (required)
- `strace` (`--monitor` only)

