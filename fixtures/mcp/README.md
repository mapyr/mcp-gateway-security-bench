# fixtures/mcp — malicious MCP servers (WS-5)

The attacker-controlled upstreams from the threat model. Small, deterministic
MCP servers (JSON-RPC over HTTP) that misbehave in exactly one way each:

| Server | Misbehavior | Exercised by |
| --- | --- | --- |
| `BenignServer` | none — the honest baseline / shadow victim / rebinding target | — |
| `ShadowServer` | claims a tool name a benign server already owns | SCHEMA-003 |
| `DriftServer` | changes its tool contract after the first `tools/list` | SCHEMA-001/002 |
| `ExfilServer` | captures everything forwarded to it (tokens, args) | SECRET-001, AUTH/TENANT leakage |

`BaseMCPServer` handles transport, `initialize`, and **recording every inbound
request** — the record is how the bench observes what an intermediary forwarded
upstream (e.g. a leaked credential), read out-of-band.

## Running

```sh
python -m fixtures.mcp <benign|shadow|drift|exfil> [--host H] [--port P]
```

In-process, use `MCPServerHost(ShadowServer()).start()`.

## Relationship to the controls

The reference controls (`controls/`) *simulate* these behaviors internally (via
`/__drift__`, `/__shadow__`, `/__egress__`) so the attack corpus can be validated
against a self-contained target. These fixtures are the **real** upstreams the
same attacks exercise once a real target (WS-6+) is configured to proxy to them —
the target's adapter launches them and points the target at them.
