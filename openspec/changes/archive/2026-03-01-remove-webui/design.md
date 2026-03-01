## Context

The web UI (`internal/webui/`) is a localhost HTTP server with SSE streaming, config editing, and run control. It is the default `--monitor` mode. The text log (`internal/textlog/`) is the alternative, writing to file or stderr. Both use `internal/logfilter/` for path shortening and nolog resolution.

The web UI is tightly integrated into `cmd/execave/main.go` (the `runMonitoredWeb` function), has its own spec (`openspec/specs/web-ui/`), dominates the `iterating-config` playbook, and is referenced by ~20 E2E tests in `monitoring_access_test.go` that assert via HTML parsing.

## Goals / Non-Goals

**Goals:**
- Remove the `internal/webui/` package and all references
- Make `--monitor` (bare) default to stderr text log (`-`) instead of web UI
- Remove `--no-open` flag
- Convert E2E tests from web UI assertions to text log assertions
- Update all documentation, specs, and playbooks

**Non-Goals:**
- Simplify the `runner` package (it still supports Start/Stop/status for potential future use)
- Add new monitoring features
- Change text log format or behavior

## Decisions

### 1. `--monitor` bare default becomes stderr

**Decision**: Change `NoOptDefVal` from `"web"` to `"-"`. Bare `--monitor` now behaves identically to `--monitor=-`.

**Why**: Stderr is the simplest default — no file path needed, output appears after process exits. The user already mentioned "stderr + file monitoring is good enough."

**Alternative considered**: Require explicit argument (no default). Rejected because it's a worse UX — `--monitor` alone should just work.

### 2. SIGINT handling simplified

**Decision**: Keep `sigCh` in `runSandboxed` for SIGINT prevention (deferred cleanup), but stop passing it to `runMonitored`. The text log path doesn't need `sigCh` — it waits for the runner status, not a signal.

**Why**: The web UI used `sigCh` to stay alive after sandbox exit (wait for user's Ctrl-C). Text log mode exits immediately when the process exits. The SIGINT prevention in `runSandboxed` is still needed so deferred cleanup (terminal restore, proxy shutdown) runs reliably.

### 3. E2E test conversion strategy

**Decision**: Convert web-UI-asserting tests to use `whenRunTextLog("-", ...)` + `thenStderrHasEntry(substrings...)`. Tests that checked OK entries add `--show-allowed` flag. Delete tests for web-UI-only behavior (survives exit, run status, SSE, page refresh).

**Why**: The monitoring behaviors (deduplication, symlink resolution, rule matching, filtering) are access log features, not web UI features. They should still be tested, just through text log output instead of HTML parsing.

**New helper**: `thenStderrHasEntry(substrings...)` — asserts a single stderr line contains all given substrings. This parallels the former `thenWebUIHasEntry` which checked an HTML `<tr>` row.

### 4. Runner package left unchanged

**Decision**: Don't simplify `runner.Runner` even though Stop/Restart and subscriber patterns are now only used in tests.

**Why**: The runner's API is clean and tested. Removing features would be a separate refactor with its own risk. The dead code is minimal overhead.

### 5. Delete web UI spec entirely

**Decision**: Delete `openspec/specs/web-ui/` rather than converting it.

**Why**: The web-ui spec describes web server behavior (SSE, HTTP endpoints, HTML rendering, token auth). None of this applies to text log. The text-log spec already covers the text log capability. Path shortening is covered by the logfilter integration tests.

## Risks / Trade-offs

**[Loss of interactive iteration loop]** → The web UI enabled edit-in-browser → restart without leaving the monitor. Users now must Ctrl-C → edit → re-run. This is intentionally accepted — the user explicitly prefers this simpler workflow.

**[E2E test coverage gap during conversion]** → Some nuanced behaviors tested via HTML (e.g., `data-nolog="true"` attribute, checkbox state) have no direct text log equivalent. → The underlying behaviors (nolog filtering, denied-only default) are tested via text log inclusion/exclusion assertions, which tests the same logic path.

**[Breaking change for `--monitor` users]** → Anyone using bare `--monitor` expecting a browser will get stderr output instead. → This is a deliberate, documented breaking change. `--monitor=<file>` is unchanged.
