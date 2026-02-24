## MODIFIED Use Cases

### Use Case: Monitor network access (HTTPS and HTTP)

The user enables monitoring with net rules to see which network endpoints the sandboxed command contacts and whether requests are allowed or denied. Both plain HTTP and CONNECT-tunneled (HTTPS) requests appear as `HTTP` operations.

- **GIVEN** a config with rules `net:http:api.example.com:443` and `net:http:internal.example.com:3000`
- **WHEN** the user runs `execave --monitor=9876 -- curl https://api.example.com/data`
- **THEN** the web UI displays an entry with operation `HTTP`, target `api.example.com:443`, result `OK`, rule `net:http:api.example.com:443`
- **AND** a denied request would appear with operation `HTTP`, target `evil.com:443`, result `DENY`, rule `no-matching-rule`

### Use Case: Monitor both filesystem and network concurrently

The user enables monitoring with both filesystem and network rules. The web UI displays both filesystem operations and network requests.

- **GIVEN** a config with rules `fs:ro:/usr/lib`, `fs:rw:/home/user/project`, and `net:http:api.example.com:443`
- **WHEN** the user runs `execave --monitor=9876 -- python script.py` (where the script reads files and makes HTTPS requests)
- **THEN** the web UI displays both `READ`/`WRITE` entries for filesystem paths and `HTTP` entries for network requests
