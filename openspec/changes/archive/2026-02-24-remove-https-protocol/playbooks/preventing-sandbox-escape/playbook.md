## MODIFIED Use Cases

### Use Case: Data exfiltration via network denied

An adversary's command attempts to exfiltrate data by making network requests to an unauthorized endpoint. The proxy denies all requests that do not match the allowlist.

- **GIVEN** a config with rules `fs:ro:/home/user/data` and `net:http:api.example.com:443`
- **WHEN** the user runs a command that reads `/home/user/data/secrets.txt` and attempts to POST it to `https://evil.com/exfil`
- **THEN** the request to `evil.com` is denied with `403 Forbidden`
- **AND** the data does not leave the sandbox
