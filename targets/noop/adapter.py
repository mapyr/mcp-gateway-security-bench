"""The `noop` target — a smoke-test placeholder, not a real intermediary.

`noop` exists so the whole pipeline (enumerate registry -> execute -> report)
can be exercised before any real target adapter or attack exists. It provisions
nothing: its endpoint is unavailable, so the runner records every sub-ID as
``INCONCLUSIVE`` — the honest verdict when there is no intermediary to ask and
no attack to run (SPEC §4, invariant #8).

This file is the reference shape for a real ``targets/<name>/adapter.py``: a
module exposing a class named ``Adapter`` implementing the
:class:`mcpsb.adapter.Adapter` protocol.
"""

from __future__ import annotations

from mcpsb.adapter import Capability, Endpoint, PolicyBundle


class Adapter:
    name = "noop"

    def provision(self, bundle: PolicyBundle) -> Endpoint:
        return Endpoint(
            available=False,
            reason="noop target: no intermediary under test",
        )

    def capabilities(self) -> set[Capability]:
        return set()

    def teardown(self) -> None:
        return None
