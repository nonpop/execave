# Execave

Filesystem and network sandbox for Linux using bubblewrap.

⚠️ Personal project, not a security expert. Uses established tools but may have configuration bugs. See `docs/security-model.md`.

## Quick Start

```bash
# Dependencies (Debian/Ubuntu)
sudo apt install bubblewrap strace

# Install
go install ./cmd/execave

# Run
execave --config execave.toml.example -- ls -la

# If execave command not found, add Go's bin directory to PATH:
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Configuration

**Filesystem rules:** `fs:<permission>:<path>` where permission is `ro`, `rw`, or `none`. More specific paths win. Paths may use `~/...` (expanded to the current user's home directory) or be relative to the config file location.

**Network rules:** `net:<protocol>:<target>:<port>` where protocol is `https`, `http`, or `none`. Target can be a domain, IP, or CIDR. Port is a number or `*` wildcard.

**Log visibility rules:** Control which entries appear in the monitor web UI. `fs:log:<path>` / `fs:nolog:<path>` show/hide filesystem entries; `net:log:<target>:<port>` / `net:nolog:<target>:<port>` show/hide network entries. Uses the same longest-prefix-match (fs) and target-specificity (net) resolution as access rules. Entries hidden by nolog rules are still enforced — this only affects display.

```toml
rules = [
  "fs:ro:/usr",
  "fs:ro:/lib",
  "fs:ro:/lib64",
  "fs:ro:/etc/ld.so.cache",

  "fs:rw:~/project",   # tilde expands to home directory
  "fs:none:.",

  "net:https:api.example.com:443",
  "net:http:*.internal.corp:*",
  "net:none:evil.example.com:443",

  "fs:nolog:/etc/fonts",            # hide known-harmless denied reads in monitor
  "net:nolog:telemetry.example.com:*",
]
```

**Automatic mounts** (not in config): `/dev`, `/proc`, `/tmp`

**Network is isolated by default.** Only connections matching net rules are allowed. The internal proxy is the only way out, so apps that ignore `HTTP_PROXY`/`HTTPS_PROXY` have no network access.

**Minimum paths vary by command.** Start with `/usr`, `/lib`, `/lib64`, `/etc/ld.so.cache` and use `--monitor` to narrow down what's actually needed.

**Note on `fs:none`:** Directories are replaced with an empty tmpfs (in-memory). More specific rules can override this—`fs:rw` under `fs:none` writes to the real filesystem. Writes to the tmpfs itself are ephemeral. Files use `/dev/null` and return permission denied.

See `execave.toml.example` for a comprehensive config that supports most standard tools.

### Building your config with --monitor

You're not expected to know every path a command needs upfront. Use `--monitor` to trace filesystem and network access in real-time via a web UI:

```bash
execave --monitor -- your-command
```

The browser opens automatically. It displays access log entries as they happen:

| Operation | Target | Result | Rule |
|-----------|--------|--------|------|
| READ | /usr/lib/libc.so.6 | OK | fs:ro:/usr |
| WRITE | /home/user/output.txt | DENY | fs:ro:/home/user |
| READ | /etc/passwd | DENY | no-matching-rule |
| HTTPS | api.example.com:443 | OK | net:https:api.example.com:443 |
| HTTP | evil.example.com:80 | DENY | no-matching-rule |

**Real-time updates:** Entries stream to the browser as syscalls happen. The server stays running after the command exits so you can review the full log. Press Ctrl-C to stop the monitor and exit.

**Filtering:** By default the web UI shows only denied entries ("Denied only" is checked). Uncheck it to see all entries. If nolog rules are configured, matching entries are also hidden; uncheck "Apply nolog rules" to reveal them.

**Config editor:** The web UI includes an editable TOML textarea. Edit the config and click Start to restart the sandbox with the new rules. Click Save to write the config to disk, or Revert to reset to the last saved version.

**Authentication:** The monitor URL includes a random access token (`?token=...`). Only requests with the correct token are served.

**Workflow:** Start with `execave.toml.example`, run with `--monitor`, check for DENY entries in the web UI (filesystem paths are shown in shortened form relative to the config directory or home), edit the config in-browser, grant only what's necessary, repeat. Use `--no-open` to suppress the automatic browser launch.

## Requirements

- Linux, Go 1.25+, `bubblewrap`, `strace` (for `--monitor`)

## Documentation

- `docs/architecture.md` - System design
- `docs/security-model.md` - Threat model and limitations

## License

MIT
