# attacks/

Attack tests, one directory per family (auth, authz, tenancy, ssrf, egress, schema, session, secrets, audit). Implemented in WS-4.

**These files must contain zero knowledge of any target** (GOVERNANCE §1.2, CLAUDE.md #3). Target differences live in `targets/<name>/adapter.py`. Verdicts come from the observation plane, never the SUT (CLAUDE.md #1).
