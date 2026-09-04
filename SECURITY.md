# Security Policy

MCPSB is a security benchmark. Running it against an intermediary produces
findings about that intermediary. This policy covers both (a) vulnerabilities in
MCPSB itself and (b) findings MCPSB produces about third-party targets.

## Reporting a vulnerability in MCPSB

Email the maintainer privately rather than opening a public issue. Include the
affected version/commit, a minimal reproduction, and the impact you observed.

## Findings MCPSB produces about a third party

These are governed by responsible disclosure — see
[`DISCLOSURE.md`](DISCLOSURE.md) for the full process. In short:

* Findings against a third-party target go to that maintainer through a private
  channel first.
* Publication of third-party `results/` is embargoed until the disclosure
  window closes or the maintainer consents (whichever comes first).
* The repository never contains working exploit code beyond the minimum needed
  to establish a PASS/FAIL verdict.

## Scope of the bench itself

MCPSB is designed to be hermetic: attack code makes **no** traffic to the real
internet. A test that would require real-internet access is `INCONCLUSIVE` by
definition. If you find attack code reaching a real external host, that is a bug
in MCPSB — report it.

## Disclaimer

Published results are **point-in-time, version-specific, and best-effort**. A
run is a targeted benchmark against specific tests and a specific target build —
**not a comprehensive security audit or certification**, and it comes with **no
warranty**. A `PASS` means one attack was blocked in one configuration; it is not
a guarantee of security. Capability claims are sourced to public documentation (or,
for the author's own target, its source) at the version noted and may change
between releases. Named products and trademarks belong to their owners; testing a
product implies no affiliation or endorsement. Use the results as one signal among
many.
