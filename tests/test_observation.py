"""Observation-plane self-tests (WS-2 DoD).

The observation plane is the verdict source of record, so it must be tested in
its own right before any attack relies on it. The two DoD checks the charter
calls out explicitly:

* rebinding genuinely changes the answer between the registration lookup and the
  connect lookup;
* the IMDS responds correctly (token handshake + credentials) and records hits.

Everything runs in-process on 127.0.0.1 — no Docker, no privileged binds.
"""

from __future__ import annotations

import json
import urllib.request

from mcpsb.observation import ObservationPlane
from mcpsb.observation.dns import DnsServer, query_a
from mcpsb.observation.imds import FAKE_CREDENTIALS, FAKE_ROLE, Imds
from mcpsb.observation.redirector import Redirector
from mcpsb.observation.sink import Sink


def _get(url: str, headers: dict | None = None, method: str = "GET") -> tuple[int, str]:
    req = urllib.request.Request(url, headers=headers or {}, method=method)
    with urllib.request.urlopen(req, timeout=3) as resp:  # noqa: S310 — localhost only
        return resp.status, resp.read().decode()


# --- DNS rebinding (the crux of SSRF-004) --------------------------------- #


def test_rebinding_changes_answer_between_resolutions():
    with DnsServer() as dns:
        dns.controller.set_rebind("rebind.mcpsb.test", ["203.0.113.10", "127.0.0.1"])
        first = query_a("rebind.mcpsb.test", dns.host, dns.port)
        second = query_a("rebind.mcpsb.test", dns.host, dns.port)
        third = query_a("rebind.mcpsb.test", dns.host, dns.port)

    assert first == "203.0.113.10", "registration lookup must be the benign IP"
    assert second == "127.0.0.1", "connect lookup must rebind to internal"
    assert third == "127.0.0.1", "rebind sticks after the flip"


def test_dns_logs_every_query_with_index():
    with DnsServer() as dns:
        dns.controller.set_static("api.example.com", "203.0.113.5")
        query_a("api.example.com", dns.host, dns.port)
        query_a("api.example.com", dns.host, dns.port)
    log = dns.controller.queries_for("api.example.com")
    assert [q.lookup_index for q in log] == [1, 2]
    assert all(q.answer == "203.0.113.5" for q in log)


def test_dns_unknown_name_returns_no_answer():
    with DnsServer() as dns:
        assert query_a("nope.invalid", dns.host, dns.port) is None


# --- IMDS ------------------------------------------------------------------ #


def test_imds_token_handshake_and_credentials():
    with Imds() as imds:
        base = imds.base_url
        status, token = _get(f"{base}/latest/api/token", method="PUT")
        assert status == 200 and token

        status, role = _get(
            f"{base}/latest/meta-data/iam/security-credentials/",
            headers={"X-aws-ec2-metadata-token": token},
        )
        assert status == 200 and role == FAKE_ROLE

        status, creds_raw = _get(
            f"{base}/latest/meta-data/iam/security-credentials/{FAKE_ROLE}",
            headers={"X-aws-ec2-metadata-token": token},
        )
        creds = json.loads(creds_raw)
        assert creds["AccessKeyId"] == FAKE_CREDENTIALS["AccessKeyId"]

    # Every hit was recorded out-of-band, and the token presence was tracked.
    assert imds.recorder.was_hit()
    assert any(h.had_token for h in imds.recorder.hits())


def test_imds_records_a_bare_hit():
    with Imds() as imds:
        _get(f"{imds.base_url}/latest/meta-data/")
    hits = imds.recorder.hits()
    assert len(hits) == 1 and hits[0].path == "/latest/meta-data/"


# --- sink ------------------------------------------------------------------ #


def test_sink_records_requests_and_serves_control_api():
    with Sink() as sink:
        _get(f"{sink.base_url}/v1/steal", headers={"Host": "evil.example"})
        # The recorded request is visible in-process...
        assert sink.recorder.count() == 1
        assert sink.recorder.received(path="/v1/steal")
        # ...and via the control API, which is not itself recorded.
        status, body = _get(f"{sink.base_url}/__mcpsb__/records")
        records = json.loads(body)
    assert status == 200
    assert len(records) == 1 and records[0]["path"] == "/v1/steal"


def test_sink_control_delete_clears():
    with Sink() as sink:
        _get(f"{sink.base_url}/hit")
        assert sink.recorder.count() == 1
        _get(f"{sink.base_url}/__mcpsb__/records", method="DELETE")
        assert sink.recorder.count() == 0


# --- redirector ------------------------------------------------------------ #


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Stops urllib from auto-following, so we can walk the chain by hand."""

    def redirect_request(self, *args, **kwargs):  # noqa: D401
        return None


def test_redirector_builds_a_chain_and_records_hops():
    opener = urllib.request.build_opener(_NoRedirect)
    with Redirector() as redir:
        # /hop/2 -> /hop/1 -> /hop/0 -> final (an internal address we never
        # actually dial — the point is the SUT would be led there).
        final = "http://169.254.169.254/latest/meta-data/"
        url = f"{redir.base_url}/hop/2?to={final}"
        seen_locations = []
        for _ in range(6):
            try:
                opener.open(url, timeout=3).close()
                break  # a 2xx would end the chain
            except urllib.error.HTTPError as e:
                assert e.code == 302
                loc = e.headers["Location"]
                seen_locations.append(loc)
                if loc == final:
                    break
                url = loc
    assert seen_locations[-1] == final
    assert redir.recorder.hop_count() == len(seen_locations)


# --- aggregate plane ------------------------------------------------------- #


def test_observation_plane_starts_all_and_resets():
    with ObservationPlane() as obs:
        _get(f"{obs.sink.base_url}/x")
        _get(f"{obs.imds.base_url}/latest/meta-data/")
        assert obs.sink.recorder.count() == 1
        assert obs.imds.recorder.was_hit()
        obs.reset()
        assert obs.sink.recorder.count() == 0
        assert not obs.imds.recorder.was_hit()
