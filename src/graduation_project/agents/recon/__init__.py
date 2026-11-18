"""Recon specialist: passive/active information gathering (nmap, nikto, curl).

Exports `ReconAgent`, which implements the `Agent` contract from
`graduation_project.core.contracts` with `agent_type = "recon"`.
"""

from graduation_project.agents.recon.agent import ReconAgent

__all__ = ["ReconAgent"]
