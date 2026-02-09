## REMOVED Requirements

### Requirement: Most specific rule wins
**Reason**: Moved to `fs-rules` capability. This defines rule resolution semantics (longest matching path prefix), which is a property of the rule engine, not of sandbox mount mechanics.
**Migration**: Requirement and all scenarios are identical in `fs-rules` spec. No behavioral change.
