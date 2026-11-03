"""Outcome vocabulary for a single objective attempt.

Richer than a binary PASSED/BLOCKED so the scheduler can decide whether to
retry, requeue, or move on. For a CTF/XBOW-style benchmark the meaningful win
is SOLVED (the flag/secret was obtained); everything else records *why* an
objective did not succeed.
"""

from enum import Enum


class Outcome(str, Enum):
    SOLVED = "SOLVED"          # objective achieved (e.g. flag captured)
    FAILED = "FAILED"          # attempted end-to-end, no success
    BLOCKED = "BLOCKED"        # a precondition is missing; cannot proceed now
    NEEDS_INFO = "NEEDS_INFO"  # depends on output from another objective
    ERROR = "ERROR"            # tooling/agent crashed


# Outcomes worth retrying later (within the budget); the rest are final.
RETRYABLE = frozenset({Outcome.BLOCKED, Outcome.NEEDS_INFO, Outcome.ERROR})
