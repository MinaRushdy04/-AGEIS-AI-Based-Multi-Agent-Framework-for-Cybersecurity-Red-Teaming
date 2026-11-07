"""Shared agent interface, re-exported from the core contract so specialists
import it from a natural place:

    from graduation_project.agents.base import Agent, Task, AgentResult, Finding
"""

from graduation_project.core.contracts import Agent, AgentResult, Finding, Task

__all__ = ["Agent", "AgentResult", "Finding", "Task"]
