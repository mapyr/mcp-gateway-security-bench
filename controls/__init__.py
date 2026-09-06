"""Reference controls: a deliberately vulnerable and a deliberately secure
intermediary sharing one codebase, differing only in policy (GOVERNANCE §3).

The differential gate rejects any attack that is not FAIL on ``vulnerable`` and
PASS on ``secure``, so ``controls/secure`` is an executable definition of what
the bench considers correct — no one has to take the spec prose on faith.
"""
