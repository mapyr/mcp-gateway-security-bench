# Agent instructions — MCPSB

These are **invariants, not preferences.** They apply to every agent working in
this repository (Claude Code, cursor-agent, or a human). `AGENTS.md` points here.

The project's rationale lives in `SPEC.md`, `THREAT_MODEL.md`, and
`GOVERNANCE.md`. Read those before making design decisions. The rules below are
the non-negotiable subset.

1. **Never derive a verdict from the system under test's logs, metrics, or API
   responses.** The verdict comes from the observation plane (sink, DNS, IMDS,
   redirector). *Exception:* `AUDIT-*` tests, where the log is the subject of
   study.

2. **Never weaken an assertion to make a test pass.** A test that is red on
   `controls/secure` means a bug in the test or in `controls/secure` — never
   "adjust the threshold."

3. **Zero target names or behaviors in `attacks/`.** Target differences live in
   `targets/<name>/adapter.py`. CI greps for target names outside `targets/` and
   `results/` and fails the build.

4. **Do not add IDs.** A new ID requires a change to `mcpsb/registry.py` in a
   separate commit prefixed `spec-change:`, with a `SPEC-CHANGELOG.md` entry.
   Never change the severity of an existing ID.

5. **Implement every surface letter.** A test family with only one of its
   declared letters is not complete (SPEC §3.2).

6. **`premise` is mandatory** and must be a sentence about a trust boundary, not
   a paraphrase of the test name.

7. **Verify against the artifact.** "The gateway should block this because its
   docs say so" is not a result. The result is what the sink recorded.

8. **A missing result is `INCONCLUSIVE`.** Never degrade to PASS or FAIL to make
   a report look complete.

9. **No traffic to the real internet from attack code.** A test needing the real
   internet is `INCONCLUSIVE` by definition.

10. **One ID per commit** in WS-4 (the attack-implementation workstream).

## Regenerating the spec

`SPEC.md` is generated. After any change to `mcpsb/registry.py`:

```
python -m mcpsb.registry --write   # regenerate SPEC.md
python -m mcpsb.registry --check   # CI gate: fails on drift
```

## Workstreams

Work proceeds one workstream per session; see the project charter. Current
status and target implementation order (`controls` → ToolHive → Docker MCP
Gateway → Hangar) are governed by `GOVERNANCE.md` §1 — Hangar is deliberately
last.
