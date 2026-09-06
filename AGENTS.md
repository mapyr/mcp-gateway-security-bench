# Agent instructions — MCPSB

The canonical, enforced invariants for every agent (including cursor-agent) live
in [`CLAUDE.md`](CLAUDE.md). Read it before making any change. It is the single
source; this file only points to it so tools that look for `AGENTS.md` find it.

The ten invariants in short form — see `CLAUDE.md` for the authoritative text:

1. Verdicts come from the observation plane, never the SUT's own logs (except
   `AUDIT-*`).
2. Never weaken an assertion to make a test pass.
3. Zero target names/behaviors in `attacks/`.
4. Don't add IDs; new IDs are a `spec-change:` commit to `mcpsb/registry.py`.
   Never change an existing severity.
5. Implement every declared surface letter.
6. `premise` is mandatory and is about a trust boundary.
7. Verify against the artifact (the sink), not documentation.
8. A missing result is `INCONCLUSIVE`, never PASS/FAIL.
9. No real-internet traffic from attack code.
10. One ID per commit in WS-4.
