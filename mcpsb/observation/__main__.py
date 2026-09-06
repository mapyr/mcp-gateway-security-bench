"""Run one observation-plane server for containerized deployment.

    python -m mcpsb.observation <sink|dns|imds|redirector> [--host H] [--port P]

Each role blocks forever. ``fixtures/net/compose.yml`` runs one container per
role with the bind address and port the networked run expects (e.g. the IMDS at
169.254.169.254:80, the DNS at :53). Configuration also reads env vars so the
compose file can set them without command args.
"""

from __future__ import annotations

import argparse
import os

from mcpsb.observation import dns, imds, redirector, sink

_DEFAULT_PORTS = {"sink": 8080, "dns": 53, "imds": 80, "redirector": 8081}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m mcpsb.observation")
    parser.add_argument("role", choices=sorted(_DEFAULT_PORTS))
    parser.add_argument("--host", default=os.environ.get("MCPSB_OBS_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument(
        "--advertised-base",
        default=os.environ.get("MCPSB_REDIRECTOR_BASE"),
        help="redirector only: base URL to advertise in Location headers",
    )
    args = parser.parse_args(argv)

    port = args.port
    if port is None:
        port = int(os.environ.get("MCPSB_OBS_PORT", _DEFAULT_PORTS[args.role]))

    print(f"mcpsb observation: {args.role} on {args.host}:{port}", flush=True)
    if args.role == "sink":
        sink.serve(args.host, port)
    elif args.role == "dns":
        dns.serve(args.host, port)
    elif args.role == "imds":
        imds.serve(args.host, port)
    elif args.role == "redirector":
        redirector.serve(args.host, port, args.advertised_base)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
