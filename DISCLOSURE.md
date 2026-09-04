# Disclosure Policy

Running MCPSB against someone else's project **produces findings**. Without a
policy, this project becomes an unpaid supplier of 0-days published in
`results/`. This document governs how findings are handled. It must be in force
before the first external target is run (WS-7 gate).

## Third-party findings

1. **Private first.** A finding against a third-party target is reported to that
   project's maintainers through their private security channel before any
   public mention.
2. **Embargo window.** Third-party `results/` are published **only** after the
   window closes or with the maintainer's consent. The window is **90 days or
   until a fix ships, whichever comes first.**
3. **Own targets: passes and non-findings are unrestricted; unfixed findings are
   not.** `results/` for a target the author maintains may be published without an
   embargo *for passes, positive observations, and inconclusives* — through the
   same pipeline as everyone else (GOVERNANCE §1.3). But the specifics of an
   **unfixed** own-target finding are **withheld** until a fix ships: publishing
   the internals of your own product's live weakness is an attack roadmap and a
   security self-harm. Fix first, re-run to confirm, then publish. This is
   stricter than a bare "own results are unrestricted," on purpose.

## Where embargoed findings live

Findings under embargo — third-party (clause 1/2) or unfixed own-target
(clause 3) — are kept in **`results/private/`**, which is in `.gitignore` and
**must never be committed**. The published tree carries passes, positive
observations, inconclusives, and pointers that "a finding is being handled
privately" — never the finding's internals. **A finding must also never enter the
git history that ships:** if one is committed by mistake, treat it as disclosed
and either complete disclosure before publishing or rewrite history to remove it
before the repo is made public/pushed.

## What a report contains

Every reported finding carries, at minimum:

* the test **ID** and its **`premise`**;
* a **reproduction** against a hermetic artifact (fixture + adapter), not prose;
* the **expected behavior**;
* a ready-to-run **regression test**.

This is the shape that has worked before: a minimal, reproducible report with a
regression test attached, not an accusation.

## Exploit code

The repository never contains working exploit code beyond what is needed to
decide PASS/FAIL. Proof-of-concept is minimal and hermetic. A finding is a
demonstration that an invariant does not hold, not a weapon.

## The maintainer's move

A maintainer who believes a finding attacks the wrong premise can respond in two
ways that the bench recognizes:

* provide a public, linked document placing the trust boundary out of their
  threat model → the result becomes `DECLARED-OUT-OF-SCOPE`, not `FAIL`;
* show the test setup is wrong → that is a bug in MCPSB and is fixed under
  `SECURITY.md`.

Neither response is treated as hostile. The point of the bench is to make the
disagreement precise, not to win an argument.
