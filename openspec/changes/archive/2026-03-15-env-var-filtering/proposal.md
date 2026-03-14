## Why

Host environment variables pass through to sandboxed processes unfiltered. This lets a sandboxed process read secrets (API keys, cloud credentials, tokens) and exfiltrate them via allowed network endpoints. The security model doc lists this as an explicit limitation with the workaround "strip secrets from the environment before invoking execave" — env filtering eliminates this gap by making execave handle it.

## What Changes

- New `env` config section with rules controlling which environment variables are visible inside the sandbox
- Default-deny: without env rules, no host env vars are passed through (tunnel-created vars like `HTTP_PROXY` are unaffected — they're created inside the sandbox, not passed from host)
- Exact variable names only (no wildcards)
- `config show` renders effective env rules with provenance
- `--no-sandbox` mode passes all env vars through unfiltered (consistent with unenforced model)

## Playbooks

### New Playbooks
- `filtering-environment`: Controlling which host environment variables are visible to sandboxed processes

### Modified Playbooks
- `preventing-sandbox-escape`: New use case for env var exfiltration prevention
- `configuring-execave`: New use cases for `env` config section syntax, validation, and error messages

## Capabilities

### New Capabilities
- `env-rules`: Parsing, validation, and resolution of environment variable rules

### Modified Capabilities
- `config`: New `env` section in TOML config; parsing, validation, deduplication, and rendering
- `tunnel`: Applies env filtering when building the user command's environment

## Impact

- **Config format**: New `env` key added to TOML. **BREAKING**: existing configs that rely on host env vars passing through will need explicit `pass` rules in the `env` section.
- **Security boundary**: Closes the env var exfiltration vector.
- **Code**: New `internal/envrules/` package; modifications to `config`, `tunnel` packages.
- **Trust boundary**: Env rules are trusted config input. The tunnel (untrusted, inside sandbox) receives only the already-filtered environment — it does not make filtering decisions.
