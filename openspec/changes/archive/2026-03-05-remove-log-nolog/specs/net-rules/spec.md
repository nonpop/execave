## REMOVED Requirements

### Requirement: Log rule syntax
**Reason**: log/nolog visibility rules removed as unnecessary complexity.
**Migration**: Remove `net:log:` and `net:nolog:` rules from config. These rules now cause a parse error.

### Requirement: Log rule validation
**Reason**: log/nolog visibility rules removed.
**Migration**: Remove `net:log:` and `net:nolog:` rules from config.

### Requirement: Log rule resolution
**Reason**: log/nolog visibility rules removed.
**Migration**: Use external log filtering (e.g., `grep`) instead.
