"""Shared implementation of the reference intermediary.

One codebase (:mod:`controls.common.intermediary`) parameterized by a
:class:`~controls.common.policy.Policy`. ``SECURE_POLICY`` turns every protection
on; ``VULNERABLE_POLICY`` turns every protection off. The two adapters
(``controls/secure`` and ``controls/vulnerable``) provision the same server with
these two policies.
"""
