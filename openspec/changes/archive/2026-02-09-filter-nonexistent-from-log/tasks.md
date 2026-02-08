## 1. E2E Test (TDD: failing test first)

- [x] 1.1 Add E2E test `TestE2E_Monitor_NonExistentPathFilteredFromLog` — nonexistent path within a rule; the read fails and log does NOT contain an entry for the path
- [x] 1.2 Update E2E test `TestE2E_Monitor_NonExistentPathNotResolved` — the read fails and log does NOT contain an entry for the path (previously asserted the path WAS in the log)
- [x] 1.3 Revert test modification in `TestE2E_Monitor_DeniedWriteLogged` — remove the `createFile` call added to work around filtering. The test should verify denied writes to nonexistent files are logged.
- [x] 1.4 Add E2E test for stat error edge case — verify that non-ENOENT stat errors (permission denied, I/O error) result in logging (fail-safe behavior)

## 2. Implementation

- [x] 2.1 Add host-side `os.Stat` existence check in `logPathAccess` — after the managed-path and dedup checks, skip the entry when `os.Stat` returns `os.ErrNotExist`. Other stat errors proceed with logging (fail-safe).
- [x] 2.2 Modify `logPathAccess` to check operation type — only filter nonexistent paths for read operations. Write operations should always be logged regardless of path existence.

## 3. Verification

- [x] 3.1 `go test ./...` — all tests pass
- [x] 3.2 `golangci-lint run --fix` — clean
