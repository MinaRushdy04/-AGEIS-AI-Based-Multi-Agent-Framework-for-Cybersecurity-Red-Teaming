"""The contract between the orchestrator and the specialist agents.

Defined in `core` so the dependency direction stays one-way: agents depend on
core, never the reverse. `agents.base` re-exports these names so agent authors
import them from a natural place.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from graduation_project.core.outcomes import Outcome
from graduation_project.core.roe import RulesOfEngagement


@dataclass
class Finding:
    """A single piece of evidence produced by an agent, persisted externally."""

    objective_id: int
    agent_type: str
    target: str
    title: str
    detail: str
    severity: str = "info"
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class Task:
    """A self-contained unit of work handed to an agent with a FRESH context.

    `context` carries only the prior findings relevant to this task's target —
    not the whole engagement history — so each agent starts clean but informed.
    """

    objective_id: int
    agent_type: str
    target: str
    description: str
    params: dict[str, Any] = field(default_factory=dict)
    context: list[Finding] = field(default_factory=list)
    roe: RulesOfEngagement | None = None


@dataclass
class AgentResult:
    """What an agent returns to the orchestrator. The agent never writes state."""

    outcome: Outcome
    summary: str
    findings: list[Finding] = field(default_factory=list)
    flag: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Agent(Protocol):
    """Every specialist (Recon, Exploit, Verifier, Reporter) implements this."""

    agent_type: str

    def run(self, task: Task) -> AgentResult: ...
