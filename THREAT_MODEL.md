# MCPSB — Threat Model

**Version:** 0.1 (draft)

## Attacker

Two attacker roles, tested separately, never assumed to collude unless a test
says so:

1. A **malicious MCP server** — it controls its own name, manifest, tool list,
   input schemas, response content, `_meta`, timing, reconnect behavior.
2. A **malicious client / agent** — it controls the token it presents,
   arguments, headers, session, request ordering, and batch composition.

The attacker does **not** control the host, the kernel, or the network beyond
what the intermediary exposes to it.

```
                    ┌─────────────────┐
   malicious client │                 │ malicious MCP server
   ─────────────────►   INTERMEDIARY  ◄─────────────────────
   (agent, token,   │   (target/SUT)  │  (manifest, schema,
    args, headers,  │                 │   responses, timing,
    session, batch) └────────┬────────┘   reconnect)
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        other tenants   internal net    credentials
                        (IMDS, RFC1918)  (env, tokens)
```

### In the attacker's control

Server name, manifest, tool list, input schemas, response bodies, `_meta`,
timing, reconnect/resumption behavior, call arguments, request headers, request
ordering, batch composition.

### Out of the model (tested elsewhere; mixing them dilutes the result)

RCE on the host, container escape, kernel attacks, physical access, breaking
cryptography.

## Assets

* **Other tenants' data and authority** — isolation must hold across tenants.
* **The internal network** — RFC1918 ranges, loopback, and cloud instance
  metadata (`169.254.169.254`) must not be reachable via a call the
  intermediary originates on a server's behalf.
* **The intermediary's own credentials** — environment, tokens — must never be
  disclosed through any argument or response path.

## Trust boundaries

Every test declares, in its `premise`, the single trust-boundary assumption it
depends on (SPEC §3.3). The threat model here is the union of those premises. A
maintainer disputing a result disputes a premise, and may place a boundary out
of scope with a public linked document, yielding `DECLARED-OUT-OF-SCOPE`.

## Layering

The full model spans three layers — **Gateway** (will the action pass?),
**Runtime** (what a malicious server does once admitted), **Governance** (can
you prove what happened later?). **v0.1 covers the Gateway layer only, plus a
minimal AUDIT slice.** Runtime and Governance are v0.3+ or never (SPEC §2). This
is a scope commitment, not a backlog note: broadening it silently would make
every result harder to interpret, which is the failure mode the whole project
exists to avoid.
