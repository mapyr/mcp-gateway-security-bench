"""Run one malicious MCP server for containerized deployment (WS-6 wires these
as upstreams of a target under test).

    python -m fixtures.mcp <benign|shadow|drift|exfil> [--host H] [--port P]
"""

from __future__ import annotations

import argparse
import os

from fixtures.mcp import BenignServer, DriftServer, ExfilServer, MCPServerHost, ShadowServer

_SERVERS = {
    "benign": BenignServer,
    "shadow": ShadowServer,
    "drift": DriftServer,
    "exfil": ExfilServer,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m fixtures.mcp")
    parser.add_argument("kind", choices=sorted(_SERVERS))
    parser.add_argument("--host", default=os.environ.get("MCPSB_FIXTURE_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("MCPSB_FIXTURE_PORT", "9000")))
    args = parser.parse_args(argv)

    import threading

    host = MCPServerHost(_SERVERS[args.kind](), args.host, args.port).start()
    print(f"mcpsb fixture: {args.kind} MCP server on {args.host}:{args.port}", flush=True)
    try:
        threading.Event().wait()
    finally:
        host.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
