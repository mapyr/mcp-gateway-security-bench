"""The observation plane (WS-2) — the bench's verdict source of record.

Independent of the system under test: an HTTP sink, a DNS server with a
rebinding zone, a fake IMDS, and a redirect server. A verdict is read from what
these recorded, never from the SUT (SPEC §3.1, invariant #1); the sole exception
is the ``AUDIT-*`` family, where the SUT's log is the subject of study.

:class:`ObservationPlane` starts all four in-process (for tests and, in WS-4,
for attacks) and is attached to ``AttackContext.observation``. For networked
runs against a containerized target, the same servers run via
``python -m mcpsb.observation <role>`` and are wired together by
``fixtures/net/compose.yml``.
"""

from __future__ import annotations

from mcpsb.observation.dns import DnsServer
from mcpsb.observation.imds import Imds
from mcpsb.observation.redirector import Redirector
from mcpsb.observation.sink import Sink

__all__ = ["ObservationPlane", "Sink", "DnsServer", "Imds", "Redirector"]


class ObservationPlane:
    """All four observation servers running together on one host."""

    def __init__(self, host: str = "127.0.0.1") -> None:
        self.sink = Sink(host)
        self.dns = DnsServer(host)
        self.imds = Imds(host)
        self.redirector = Redirector(host)

    def start(self) -> "ObservationPlane":
        self.sink.start()
        self.dns.start()
        self.imds.start()
        self.redirector.start()
        return self

    def stop(self) -> None:
        for server in (self.sink, self.dns, self.imds, self.redirector):
            try:
                server.stop()
            except Exception:  # noqa: BLE001 — best-effort teardown
                pass

    def reset(self) -> None:
        """Clear all recorders between tests, keeping the servers running."""
        self.sink.recorder.clear()
        self.dns.controller.clear()
        self.imds.recorder.clear()
        self.redirector.recorder.clear()

    def __enter__(self) -> "ObservationPlane":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()
