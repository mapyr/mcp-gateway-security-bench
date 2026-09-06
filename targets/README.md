# targets/

One directory per intermediary under test: `compose.yml` + policy templates + `adapter.py`.

Implementation order (GOVERNANCE §1.1): ToolHive → Docker MCP Gateway → agentgateway / ContextForge → Hangar. Hangar is deliberately last.

An adapter implements `provision(policy_bundle) -> Endpoint`, `capabilities() -> set[Capability]`, `teardown()`. What it cannot express becomes UNSUPPORTED, never a hack in an attack.
