## Context

Bwrap's `--new-session` calls `setsid()`, which creates a new session and detaches the sandboxed process from the controlling terminal. This prevents TIOCSTI injection (CVE-2017-5226) where a sandboxed process pushes characters into the terminal input queue to execute commands on the host.

The side effect: SIGWINCH (terminal resize signal) is delivered to the foreground process group of the controlling terminal. After `setsid()`, the sandboxed process is in a different session and never receives SIGWINCH, breaking TUI auto-resize.

Since Linux 6.2, `CONFIG_LEGACY_TIOCSTI` defaults to disabled. The sysctl `/proc/sys/dev/tty/legacy_tiocsti` reads `0` on these kernels, meaning TIOCSTI is blocked at the kernel level regardless of session boundaries.

## Goals / Non-Goals

**Goals:**
- Restore SIGWINCH delivery to sandboxed TUI apps on modern kernels
- Maintain TIOCSTI protection on older kernels via `--new-session`
- Fail-safe: when kernel status is unknown, assume TIOCSTI is enabled

**Non-Goals:**
- Seccomp-based TIOCSTI blocking (alternative approach, higher complexity)
- PTY relay for SIGWINCH forwarding across session boundaries
- User-configurable override for `--new-session`

## Decisions

### Decision: Check `/proc/sys/dev/tty/legacy_tiocsti` at sandbox build time

Read the sysctl at `BuildBwrapArgs` time. If it reads `0`, skip `--new-session`. If it reads anything else, is absent, or is unreadable, include `--new-session`.

**Why at build time:** The sysctl value is system-wide and stable — it doesn't change during execution. Reading it once per sandbox invocation is sufficient.

**Why in `BuildBwrapArgs`:** This is where `--new-session` is currently added. The detection is a pure input to bwrap arg construction, so it belongs here.

**Alternatives considered:**
- Check at `New()` time: Would work but couples detection to construction rather than arg building. `BuildBwrapArgs` is also called directly by the monitor, so the check needs to be there.
- Cache across invocations: Unnecessary — execave runs one sandbox per invocation.

### Decision: Unexported detection function

Create `tiocSTIBlocked() bool` in the sandbox package. This reads and parses the sysctl. `BuildBwrapArgs` calls it internally. Unit tests (white-box, same package) can test the function directly. Integration and E2E tests verify behavior through `BuildBwrapArgs` output.

### Decision: Fail-safe default

If the sysctl file doesn't exist (pre-6.2 kernel) or can't be read (permissions, unexpected format), return `false` (TIOCSTI not blocked) and `--new-session` is used. This is the secure default — we only skip `--new-session` when we have positive confirmation that the kernel blocks TIOCSTI.

**Threat analysis — what if detection is wrong?**
- False positive (thinks TIOCSTI blocked when it isn't): Sandbox omits `--new-session`, TIOCSTI injection possible. Mitigated by: only trusting the kernel sysctl, which is authoritative. A false positive requires a kernel bug.
- False negative (thinks TIOCSTI enabled when it isn't): Sandbox includes `--new-session` unnecessarily, TUI resize broken. This is the safe direction — no security impact, just UX degradation.

### Decision: Update security model documentation

The "Sandboxed process can't inject terminal input" guarantee in `docs/security-model.md` currently cites only `--new-session`. Update to describe the conditional mechanism: kernel TIOCSTI disabling on modern systems, `--new-session` fallback on older ones.

## Risks / Trade-offs

**[Risk] Sysctl removed or renamed in future kernels** → The fail-safe default uses `--new-session` if the file is missing, so future kernel changes degrade to the current behavior, not to an insecure state.

**[Risk] Container environments where `/proc/sys` is mounted read-only or filtered** → `os.ReadFile` on a read-only procfs still works. If the file is filtered/absent, the fail-safe applies.

**[Trade-off] No resize on old kernels** → Accepted. The alternative (seccomp) was considered and rejected for complexity. Users on pre-6.2 kernels can upgrade or accept the limitation.
