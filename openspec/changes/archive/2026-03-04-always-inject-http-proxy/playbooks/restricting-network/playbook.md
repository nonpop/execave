## MODIFIED Use Cases

### Use Case: Run command with no network access (default-deny)

The user runs a command without any net rules in the config. The sandbox has no network interface. The proxy tunnel is always active with a deny-all rule set, so HTTP-proxy-aware clients receive `403 Forbidden`; clients that bypass `HTTP_PROXY` fail because there is no NIC.

- **GIVEN** a config with only filesystem rules (no `net:` rules)
- **WHEN** the user runs `execave -- curl https://example.com`
- **THEN** curl, which respects `HTTP_PROXY`, receives `403 Forbidden` from the proxy (deny-all, no matching rule)
- **AND** DNS resolution also fails (no network interface for direct resolution)
