"""Helpers for honest real-target provisioning (invariant #8).

A real-target adapter must never bring its target up in a partial or insecure
configuration and report the resulting spurious failures — that is a config
artifact, not a finding. When the prerequisites for a faithful run are absent,
the adapter returns an *unavailable* :class:`~mcpsb.adapter.Endpoint`, and the
runner records every test as ``INCONCLUSIVE``.

``preflight`` centralizes the two common prerequisites: the target's CLI/binary
being installed, and the environment that a fully-configured secure harness must
provide. It returns an unavailable Endpoint (with a precise reason) if anything
is missing, or ``None`` to signal "go ahead and provision".
"""

from __future__ import annotations

import os
import shutil

from mcpsb.adapter import Endpoint


def preflight(
    *,
    binary: str,
    required_env: tuple[str, ...] = (),
    docs: str = "",
) -> Endpoint | None:
    """Return an unavailable Endpoint if prerequisites are missing, else None.

    ``binary`` is the CLI that must be on PATH; ``required_env`` are environment
    variables the secure harness must set; ``docs`` is a path to point the reader
    at for setup.
    """
    where = f" (see {docs})" if docs else ""
    if shutil.which(binary) is None:
        return Endpoint(available=False, reason=f"{binary} not installed{where}")
    missing = [k for k in required_env if not os.environ.get(k)]
    if missing:
        return Endpoint(
            available=False,
            reason=(
                f"live harness not configured; missing {', '.join(missing)}{where}. "
                "Reporting INCONCLUSIVE rather than provisioning an insecure config."
            ),
        )
    return None
