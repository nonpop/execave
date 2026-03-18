## ADDED Use Cases

### Use Case: Pass rule for proxy-managed env var is rejected as a config error

The user accidentally adds a pass rule for `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`, or `no_proxy`. These variables are managed by the tunnel and are always injected or stripped automatically — passing them from the host has no effect and indicates a misconfiguration.

- **GIVEN** a config with `env = ["pass:HTTP_PROXY"]`
- **WHEN** the user runs `execave -- true`
- **THEN** execave exits with a non-zero status
- **AND** stderr contains an error message indicating that `HTTP_PROXY` is managed by the tunnel and cannot be passed from the host

### Use Case: Pass rule for lowercase proxy env var is rejected as a config error

- **GIVEN** a config with `env = ["pass:no_proxy"]`
- **WHEN** the user runs `execave -- true`
- **THEN** execave exits with a non-zero status
- **AND** stderr contains an error message indicating that `no_proxy` is managed by the tunnel
