"""The runner (WS-1).

Enumerates the registry, runs each test on each declared surface against a
target adapter, and assembles a :class:`~mcpsb.report.Report`. The verdict logic
here encodes the SPEC rules that do not depend on any specific attack:

* Target could not be provisioned  -> every sub-ID ``INCONCLUSIVE`` (never
  PASS/FAIL — invariant #8).
* Target does not expose the surface -> ``UNSUPPORTED`` (SPEC §4), from the
  adapter's declared capabilities, never a guess.
* No attack registered for the sub-ID -> ``INCONCLUSIVE`` ("harness did not
  establish the test"). This is why ``--target noop`` reports all-INCONCLUSIVE
  in WS-1: the pipeline is whole, but no attack is wired in yet.
* Attack raises ``UnsupportedPolicy`` -> ``UNSUPPORTED``; any other exception ->
  ``ERROR``; a non-Verdict return -> ``ERROR``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from mcpsb.adapter import (
    SURFACE_CAPABILITY,
    Adapter,
    Endpoint,
    PolicyBundle,
    ProvisionError,
    UnsupportedPolicy,
)
from mcpsb.capabilities import is_policy_supported, missing_capabilities
from mcpsb.registry import REGISTRY, SURFACE_LABELS, TestSpec, active_tests
from mcpsb.report import Report
from mcpsb.testkit import (
    AttackContext,
    PositiveControl,
    RegisteredAttack,
    all_positive_controls,
    family_of,
    get_attack,
)
from mcpsb.verdict import (
    POSITIVE_CONTROL_MISSING,
    PositiveControlResult,
    Result,
    Verdict,
    validate_evidence,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# Adapter loading.
# --------------------------------------------------------------------------- #


#: Directories searched for a target's adapter, in order. `controls/` holds the
#: reference intermediary variants (secure, vulnerable); `targets/` holds real
#: targets. The two share the adapter convention so the runner treats a control
#: exactly like any other target.
_ADAPTER_DIRS = ("controls", "targets")


def load_adapter(name: str, root: Path = _REPO_ROOT) -> Adapter:
    """Load ``<controls|targets>/<name>/adapter.py`` and instantiate ``Adapter``.

    This is the one convention every target follows (charter §8): a directory
    per target with an ``adapter.py`` exposing a class named ``Adapter`` that
    satisfies the :class:`~mcpsb.adapter.Adapter` protocol.
    """
    path = next(
        (root / d / name / "adapter.py" for d in _ADAPTER_DIRS
         if (root / d / name / "adapter.py").exists()),
        None,
    )
    if path is None:
        searched = ", ".join(f"{d}/{name}/adapter.py" for d in _ADAPTER_DIRS)
        raise FileNotFoundError(f"no adapter for target {name!r}: none of {searched}")
    spec = importlib.util.spec_from_file_location(f"mcpsb_target_{name}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not load adapter module at {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    adapter_cls = getattr(module, "Adapter", None)
    if adapter_cls is None:
        raise AttributeError(f"{path} does not define an `Adapter` class")
    return adapter_cls()


# --------------------------------------------------------------------------- #
# Execution.
# --------------------------------------------------------------------------- #


def _run_positive_control(
    pc: PositiveControl,
    endpoint: Endpoint,
    observation: object | None,
    scenario: object | None,
    client_factory: object | None,
) -> PositiveControlResult:
    """Run one family's positive control against a provisioned target (WS-D2)."""
    if not endpoint.available:
        return PositiveControlResult(
            pc.family, Verdict.INCONCLUSIVE,
            endpoint.reason or "target was not provisioned",
        )
    ctx = AttackContext(
        sub_id=f"{pc.family}-PC",
        test_id=f"{pc.family}-PC",
        surface="+",
        endpoint=endpoint,
        bundle=PolicyBundle.empty(),
        observation=observation,
        scenario=scenario,
        client_factory=client_factory,
    )
    ctx.evidence_source = pc.evidence_source
    try:
        verdict = pc.fn(ctx)
    except UnsupportedPolicy as exc:
        return PositiveControlResult(pc.family, Verdict.UNSUPPORTED, str(exc))
    except Exception as exc:  # noqa: BLE001 — a broken control is INCONCLUSIVE, not a pass
        return PositiveControlResult(
            pc.family, Verdict.INCONCLUSIVE, f"{type(exc).__name__}: {exc}"
        )
    if not isinstance(verdict, Verdict):
        return PositiveControlResult(
            pc.family, Verdict.INCONCLUSIVE,
            f"positive control returned {type(verdict).__name__}",
        )
    # A positive control is only conclusive as PASS/FAIL; keep INCONCLUSIVE/
    # UNSUPPORTED as-is. Its evidence source is recorded for the matrix row.
    source = pc.evidence_source if verdict in (Verdict.PASS, Verdict.FAIL) else None
    return PositiveControlResult(pc.family, verdict, ctx.reason, source)


def run_positive_controls(
    endpoint: Endpoint,
    observation: object | None,
    scenario: object | None,
    client_factory: object | None,
) -> list[PositiveControlResult]:
    """Run every registered family positive control, in family order (WS-D2)."""
    return [
        _run_positive_control(pc, endpoint, observation, scenario, client_factory)
        for pc in all_positive_controls()
    ]


def _evaluate(
    spec: TestSpec,
    letter: str,
    endpoint: Endpoint,
    capabilities: set,
    attack: RegisteredAttack | None,
    observation: object | None = None,
    scenario: object | None = None,
    client_factory: object | None = None,
    verified_families: frozenset | None = None,
    version_ok: bool = True,
    version: str = "",
    tested: str = "",
) -> Result:
    sub_id = f"{spec.id}.{letter}"

    def result(verdict: Verdict, reason: str = "", evidence: dict | None = None,
               evidence_source=None) -> Result:
        return Result(
            sub_id=sub_id,
            test_id=spec.id,
            surface=letter,
            severity=spec.severity,
            verdict=verdict,
            reason=reason,
            evidence_source=evidence_source,
            evidence=evidence or {},
        )

    if not endpoint.available:
        return result(
            Verdict.INCONCLUSIVE, endpoint.reason or "target was not provisioned"
        )

    if SURFACE_CAPABILITY[letter] not in capabilities:
        return result(
            Verdict.UNSUPPORTED,
            f"target does not expose surface {letter} ({SURFACE_LABELS[letter]})",
        )

    if not is_policy_supported(spec.id, capabilities):
        missing = missing_capabilities(spec.id, capabilities)
        names = ", ".join(sorted(c.value for c in missing))
        return result(
            Verdict.UNSUPPORTED,
            f"target cannot express the policy this test requires (needs {names})",
        )

    if attack is None or letter not in attack.surfaces:
        return result(
            Verdict.INCONCLUSIVE, "no attack implementation for this sub-ID"
        )

    ctx = AttackContext(
        sub_id=sub_id,
        test_id=spec.id,
        surface=letter,
        endpoint=endpoint,
        bundle=PolicyBundle.empty(),
        observation=observation,
        scenario=scenario,
        client_factory=client_factory,
    )
    # D1: the attack declared its evidence source at registration; stamp it on the
    # context so a conclusive verdict carries it. An attack may still override it.
    ctx.evidence_source = attack.evidence_source
    try:
        verdict = attack.fn(ctx)
    except UnsupportedPolicy as exc:
        return result(Verdict.UNSUPPORTED, str(exc))
    except Exception as exc:  # noqa: BLE001 — any attack fault is an ERROR, not a FAIL
        return result(Verdict.ERROR, f"{type(exc).__name__}: {exc}")

    if not isinstance(verdict, Verdict):
        return result(
            Verdict.ERROR,
            f"attack returned {type(verdict).__name__}, expected a Verdict",
        )
    # D1: a conclusive verdict must carry a valid evidence_source, or it ERRORs.
    verdict, source, err = validate_evidence(spec.id, verdict, ctx.evidence_source)
    if err:
        return result(Verdict.ERROR, err, ctx.evidence)
    # Tested-version gate: refuse to publish a PASS/FAIL for a build outside the
    # adapter's tested range (or one whose version could not be sourced). ERROR,
    # never a verdict the bench cannot stand behind for this build.
    if verdict in (Verdict.PASS, Verdict.FAIL) and not version_ok:
        shown = version or "unknown"
        return result(
            Verdict.ERROR,
            f"verdict withheld: version {shown!r} is outside the tested range "
            f"({tested or 'declared by the adapter'}); the bench does not opine on "
            f"builds it has not reviewed",
        )
    # D2: a PASS only counts if this family's positive control was verified on
    # this target. Otherwise "blocked" is indistinguishable from "blocks
    # everything", so the PASS degrades to INCONCLUSIVE. FAIL is unaffected — an
    # observed breach is real regardless.
    if (
        verdict is Verdict.PASS
        and verified_families is not None
        and family_of(spec.id) not in verified_families
    ):
        return result(
            Verdict.INCONCLUSIVE,
            f"{POSITIVE_CONTROL_MISSING}: no verified positive control for family "
            f"{family_of(spec.id)} on this target; a block here is not distinguishable "
            f"from blocking everything",
        )
    return result(verdict, ctx.reason, ctx.evidence, evidence_source=source)


def run(
    adapter: Adapter,
    registry: tuple[TestSpec, ...] = REGISTRY,
    generated_at: str = "",
    observation: object | None = None,
) -> Report:
    """Run every active test on every declared surface against ``adapter``.

    ``observation`` is the running observation plane (WS-2), attached to each
    attack's context so verdicts are read from it, never from the SUT. Its
    lifecycle (start/stop) is the caller's; the runner only threads it through.
    """
    capabilities = set(adapter.capabilities())
    try:
        endpoint = adapter.provision(PolicyBundle.empty())
        if observation is not None and hasattr(adapter, "wire_observation"):
            adapter.wire_observation(observation)
    except ProvisionError as exc:
        endpoint = Endpoint(available=False, reason=str(exc))

    scenario = adapter.scenario() if hasattr(adapter, "scenario") else None
    client_factory = adapter.client_factory() if hasattr(adapter, "client_factory") else None

    # Tested-version gate: the version is sourced from the artifact, and if the
    # adapter declares a tested range the run refuses to opine (PASS/FAIL -> ERROR)
    # on a build outside it — a stale build must not yield a "correct but years
    # out of date" verdict.
    version = adapter.version() if hasattr(adapter, "version") else ""
    if hasattr(adapter, "supports_version"):
        version_ok = adapter.supports_version(version)
        tested = adapter.tested_versions() if hasattr(adapter, "tested_versions") else ""
    else:
        version_ok, tested = True, ""

    # D2: establish which families accept their legitimate request before running
    # attacks, so a PASS in an unverified family can degrade to INCONCLUSIVE.
    positive_controls = run_positive_controls(
        endpoint, observation, scenario, client_factory
    )
    verified_families = frozenset(p.family for p in positive_controls if p.verified)
    if observation is not None and hasattr(observation, "reset"):
        observation.reset()  # positive controls touched the sink/DNS; start attacks clean

    results: list[Result] = []
    try:
        for spec in active_tests(registry):
            attack = get_attack(spec.id)
            for letter in spec.surfaces:
                results.append(
                    _evaluate(
                        spec, letter, endpoint, capabilities, attack,
                        observation, scenario, client_factory, verified_families,
                        version_ok, version, tested,
                    )
                )
    finally:
        adapter.teardown()

    return Report(
        target=adapter.name,
        version=version,
        results=results,
        generated_at=generated_at,
        positive_controls=positive_controls,
    )
