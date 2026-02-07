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
execave --config execave.json.example -- ls -la

# If execave command not found, add Go's bin directory to PATH:
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Configuration

**Filesystem rules:** `fs:<permission>:<path>` where permission is `ro`, `rw`, or `none`. More specific paths win.

**Network rules:** `net:<protocol>:<target>:<port>` where protocol is `https`, `http`, or `none`. Target can be a domain, IP, or CIDR. Port is a number or `*` wildcard.

```json
{
  "rules": [
    "fs:ro:/usr",
    "fs:ro:/lib",
    "fs:ro:/lib64",
    "fs:ro:/etc/ld.so.cache",

    "fs:rw:/home/user/project",
    "fs:none:.",

    "net:https:api.example.com:443",
    "net:http:*.internal.corp:*",
    "net:none:evil.example.com:443"
  ]
}
```

**Automatic mounts** (not in config): `/dev`, `/proc`, `/tmp`

**Network is isolated by default.** Only connections matching net rules are allowed. The internal proxy is the only way out, so apps that ignore `HTTP_PROXY`/`HTTPS_PROXY` have no network access.

**Minimum paths vary by command.** Start with `/usr`, `/lib`, `/lib64`, `/etc/ld.so.cache` and use `--monitor` to narrow down what's actually needed.

**Note on `fs:none`:** Directories are replaced with an empty tmpfs (in-memory). More specific rules can override this—`fs:rw` under `fs:none` writes to the real filesystem. Writes to the tmpfs itself are ephemeral. Files use `/dev/null` and return permission denied.

See `execave.json.example` for a comprehensive config that supports most standard tools.

### Building your config with --monitor

You're not expected to know every path a command needs upfront. Use `--monitor` to trace filesystem access while enforcing sandbox rules:

```bash
execave --monitor -- your-command
cat execave-access.log
```

```
READ   /usr/lib/libc.so.6       OK     fs:ro:/usr
WRITE  /home/user/output.txt    DENY   fs:ro:/home/user
READ   /etc/passwd              DENY   no-matching-rule
HTTPS  api.example.com:443      OK     net:https:api.example.com:443
HTTP   evil.example.com:80      DENY   no-matching-rule
```

Each line: operation, target, result (OK/DENY), matching rule. Network entries (`HTTPS`/`HTTP`) appear when net rules are configured.

**Workflow:** Start with `execave.json.example`, run with `--monitor`, check for DENY entries, grant only what's necessary, repeat.

## Requirements

- Linux, Go 1.25+, `bubblewrap`, `strace` (for `--monitor`)

## Documentation

- `docs/architecture.md` - System design
- `docs/security-model.md` - Threat model and limitations

## License

MIT
