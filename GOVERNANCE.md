# MCPSB — Governance

**Version:** 0.1 (draft)

This document exists to answer one question a skeptical reader will ask on day
one: *the author maintains one of the targets — why should I trust the results?*
The rules below are the answer, and they are enforced in CI wherever a machine
can enforce them.

## 1. Conflict of interest

One of the intended targets (MCP Hangar) is maintained by the author of this
bench. That is the single risk that can end the project's credibility and the
only one that cannot be repaired after the fact. The following are hard rules.

1. **Target implementation order: `controls` → ToolHive → Docker MCP Gateway →
   Hangar.** Hangar is fourth. If Hangar were first, the harness would grow
   around its configuration model and every later adapter would fight it — and
   any external reader would see exactly that in the git history.

2. **Zero target-specific code in `attacks/`.** CI gate: a grep for target
   names outside `targets/` and `results/` fails the build
   (`ci/check_no_target_leak.py`). Target differences live in
   `targets/<name>/adapter.py`, nowhere else.

3. **Hangar's results are published in `results/` on the same terms as anyone
   else's** — through the same pipeline, the same adapter contract, with no
   hand-tuning of configuration "to make it pass."

4. **No MCPSB result appears in Hangar's marketing until at least one external
   maintainer has published their own run.** Until then a "tested against
   MCPSB" badge is self-reference.

5. **Terminology.** The repository is named `mcp-gateway-security-bench` for
   discoverability, but `SPEC.md` defines the object under test as an
   **intermediary**: "any component that sits on the path between an MCP client
   and an MCP server and makes a decision about the call."

## 2. Neutrality of the test corpus

* Tests are functions under `attacks/`, decorated with the test ID. They must
  contain no knowledge of any specific target — not its name, not its
  configuration format, not its quirks.
* What a target can and cannot express is declared by that target's adapter via
  `capabilities()`. The adapter's declaration is what produces an `UNSUPPORTED`
  verdict — the bench never guesses.
* The `policy_bundle` is a conformance contract: a set of policy *intents* a
  target must be able to express in its own syntax. If an adapter cannot
  translate an intent, the result is `UNSUPPORTED`, never a workaround in the
  attack.

## 3. The differential gate

`controls/vulnerable` and `controls/secure` are two variants of the same minimal
intermediary. **CI rejects any test that is not FAIL on `vulnerable` and PASS on
`secure`.** A test without both results does not exist. Beyond catching
mis-written tests, `controls/secure` becomes an executable definition of what
the bench considers correct — no one has to take the spec prose on faith.

## 4. Changing the spec

* Test IDs are never renumbered and severities are never edited in place
  (SPEC §5). A change of expected behavior is a new ID plus deprecation of the
  old one.
* Adding or deprecating an ID, or changing a severity, requires a commit whose
  message is prefixed `spec-change:` and a corresponding entry in
  [`SPEC-CHANGELOG.md`](SPEC-CHANGELOG.md).
* `SPEC.md` is generated from `mcpsb/registry.py`. CI fails on drift
  (`ci/check_spec_drift.py`) and on any severity change relative to the last tag
  that is not accompanied by a `spec-change:` commit
  (`ci/check_severity_freeze.py`).

## 5. Disclosure

Running the bench against a third party produces findings. Handling of those
findings is governed by [`SECURITY.md`](SECURITY.md) and
[`DISCLOSURE.md`](DISCLOSURE.md), which must be in force before the first
external target is run.
