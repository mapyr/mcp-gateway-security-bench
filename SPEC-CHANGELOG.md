# SPEC Changelog

Every change to the test registry — adding an ID, deprecating an ID, or changing
an ID's severity — is recorded here and made in a commit whose message is
prefixed `spec-change:`. IDs are never renumbered; severities are never edited
in place (SPEC §5). CI enforces both (`ci/check_severity_freeze.py`).

The format is loosely [Keep a Changelog](https://keepachangelog.com/). Entries
are newest-first.

## [Unreleased]

### Added — v0.1 initial registry (23 IDs)

The founding registry. All 23 IDs are introduced together, so there is no prior
tag to diff against; the severity-freeze gate begins comparing from the first
tagged release.

`AUTH-001`–`AUTH-004`, `AUTHZ-001`–`AUTHZ-004`, `TENANT-001`–`TENANT-002`,
`SSRF-001`–`SSRF-005`, `EGRESS-001`, `SCHEMA-001`–`SCHEMA-003`, `SESSION-001`,
`SECRET-001`, `AUDIT-001`–`AUDIT-002`.

See `SPEC.md` (generated) for each ID's severity, surfaces, and premise.
