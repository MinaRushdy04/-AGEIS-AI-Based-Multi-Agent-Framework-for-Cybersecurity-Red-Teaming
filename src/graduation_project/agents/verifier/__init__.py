"""Verifier specialist: confirms Exploit findings have real evidence
(payload + response, not just a bare claim) before treating them as solved.

Exports `VerifierAgent` (`agent_type = "verifier"`).
"""

from graduation_project.agents.verifier.agent import VerifierAgent

__all__ = ["VerifierAgent"]
