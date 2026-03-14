## Context

Host environment variables currently pass through to sandboxed processes unfiltered. The security model doc explicitly lists this as a limitation. This design adds a `pass:VAR` rule mechanism in the config's `env` section that controls which host env vars enter the sandbox, using bwrap's `--clearenv`/`--setenv` flags as the enforcement point.

Current env flow:
1. Host env → bwrap (passes all through, no `--clearenv`) → tunnel → user command
2. Tunnel's `buildEnv` strips proxy vars and injects its own `HTTP_PROXY`/`HTTPS_PROXY`

After this change:
1. Host env → bwrap (`--clearenv` + `--setenv` for each passed var) → tunnel → user command
2. Tunnel's `buildEnv` is unchanged — it sees only what bwrap allowed through

## Goals / Non-Goals

**Goals:**
- Default-deny: no host env vars visible in sandbox unless explicitly passed
- Filtering enforced at the bwrap boundary (kernel-level, not process-level)
- Consistent rule syntax and validation patterns with existing rule types
- `config show` renders env rules with provenance
- No-sandbox mode passes all env vars through (consistent with unenforced model)

**Non-Goals:**
- Wildcard or pattern matching for variable names
- Setting arbitrary values (only forwarding host values)
- Access logging for env vars (filtering is one-shot at startup, not runtime)
- Filtering tunnel-created vars (`HTTP_PROXY` etc. are injected inside the sandbox)

## Decisions

### D1: Enforce via bwrap `--clearenv` + `--setenv`

Add `--clearenv` to bwrap args, then `--setenv KEY VALUE` for each `pass` rule where the variable exists in the host environment. Variables listed in `pass` rules but absent from the host env are silently skipped (not an error — the host simply doesn't have it).

**Why not filter in the tunnel's `buildEnv`?** The tunnel runs inside the sandbox. If bwrap passes all env vars through, a compromised tunnel (or any process that runs before the tunnel's filtering) could read secrets. Filtering at bwrap means the kernel namespace boundary enforces the policy — the secret never enters the sandbox at all.

**Why `--clearenv` + `--setenv` instead of `--unsetenv`?** Default-deny requires starting clean. Using `--unsetenv` for every non-allowed var is fragile (must enumerate all host vars) and violates the fail-safe principle — a new host var would leak through by default.

**Alternatives considered:** Filtering in the Go process before exec (setting `cmd.Env`) — rejected because bwrap inherits from its parent, so we'd need bwrap-level flags anyway.

### D2: Always use `--clearenv` when env rules are present in config

When the config has an `env` section (even if empty — which means "pass nothing"), bwrap gets `--clearenv` plus `--setenv` for each rule. When there is no `env` section at all, the behavior is also default-deny: no host vars pass through. This means `--clearenv` is always added in sandboxed mode.

**Why always?** The proposal specifies default-deny. Without `--clearenv`, all host vars leak. Adding it unconditionally is the simplest fail-safe design — there's no mode where host vars silently pass through.

**Risk:** Existing users who rely on host env vars passing through will break. The proposal already marks this as a **BREAKING** change — users must add explicit `pass` rules.

### D3: New `internal/envrules/` package

Follows the established rule package pattern:
- `Rule` struct: `Name string`, `RawRule string`, `SourcePath string`
- `Canonical() string` returns `"pass:NAME"`
- `ParseRule(rawRule, configPath string) (Rule, error)` — validates action is `pass`, name is non-empty
- `ValidateRules(rules []Rule) error` — rejects duplicates (same `Canonical()`)

Includes a `Resolver` for symmetry with other rule packages:
- `NewResolver(rules []Rule) *Resolver`
- `Resolve(environ []string) []EnvVar` — takes the host environment (e.g. from `os.Environ()`), returns the filtered `KEY=VALUE` pairs to pass into the sandbox. Only vars with a matching `pass` rule are included; absent host vars are silently skipped.

The resolver encapsulates the filtering logic so the sandbox doesn't iterate rules directly.

### D4: Sandbox receives env rules via `Config`

`config.Config` gains an `EnvRules []envrules.Rule` field. The sandbox constructs an `envrules.Resolver` and calls `Resolve(os.Environ())` to get the `--setenv` pairs for bwrap args.

This runs in the host process before exec, so `os.Environ()` reflects the full host environment.

### D5: No-sandbox mode skips env filtering entirely

In `--no-sandbox` mode, `cmd.Env` remains unset (Go default: inherit parent env). This is consistent with no-sandbox skipping all other enforcement (filesystem, network, seccomp). The env rules in config are ignored, same as fs/net rules are ignored in this mode.

### D6: Config parsing and merging

- `rawConfig` gains `Env []string` with TOML tag `env`
- `buildConfig` parses each entry via `envrules.ParseRule` and validates via `envrules.ValidateRules`
- `mergeEnvRules` follows the identical dedup pattern of `mergeFSRules`/`mergeNetRules`/`mergeSyscallRules`: `seen` map keyed by `Canonical()`, skip duplicates, re-validate merged result
- `RenderEffectiveTOML` gains a `renderEnvRules` function and `appendSection` call for the `env` key

## Risks / Trade-offs

**Breaking change for existing users** → Mitigated by clear error messaging. When a sandboxed command fails because a needed env var is missing, the user adds `pass:VAR` rules. The `config show` command helps audit the effective env rules.

**Silent skip of absent host vars** → A `pass:HOME` rule when HOME is unset on the host silently results in HOME being unset in the sandbox. This is correct (can't forward what doesn't exist) but could surprise users. No mitigation needed — this matches how bwrap's `--setenv` works and is the least surprising behavior.

**Tunnel's `buildEnv` starts from `os.Environ()`** → Inside the sandbox, `os.Environ()` returns only what bwrap allowed through. The tunnel then strips proxy vars and adds its own. This means tunnel-created proxy vars are always present regardless of env rules — which is the desired behavior. No code change needed in the tunnel. Risk: if the tunnel's behavior changes to depend on specific host vars, those would need `pass` rules. Current tunnel code only depends on its own CLI args and the proxy URL, so this is safe.

**`--clearenv` removes bwrap-internal vars** → bwrap itself doesn't rely on env vars for its operation (it uses CLI flags). The `--clearenv` applies to the child process, not to bwrap's own execution. Verified by bwrap documentation: `--clearenv` "unsets all environment variables" for the sandboxed process.
