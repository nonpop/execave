## 1. E2E Tests (write first per TDD)

- [x] 1.1 Add e2e test cases to `test/e2e/cli_rules_test.go` for `--env pass:HTTP_PROXY`, `--env pass:HTTPS_PROXY`, and `--env pass:no_proxy` each expecting exit code 1 and stderr containing a "managed by the tunnel" error message

## 2. Core Implementation

- [x] 2.1 Add rejection of proxy-managed variable names in `internal/envrules/envrules.go` `ParseRule`: after the empty-name check, reject `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`, `no_proxy` with an error of the form `env rule %q: %s is managed by the tunnel and cannot be passed from the host`

## 3. Documentation

- [x] 3.1 Fix `README.md` line 76: remove "or via env rules" from the `NO_PROXY` suggestion in the intra-sandbox servers paragraph
