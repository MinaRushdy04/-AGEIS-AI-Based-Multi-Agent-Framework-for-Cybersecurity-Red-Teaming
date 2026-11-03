"""Engagement state: the plan, its objectives, and their lifecycle.

Plain, serialisable data owned by the orchestrator. Agents never mutate it;
they return results and the orchestrator records them here. Scheduling is
phase-ordered and deterministic, which keeps benchmark runs reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum

from graduation_project.core.outcomes import Outcome


class Phase(IntEnum):
    """Engagement phases in execution order. Lower numbers run first."""

    RECON = 1
    ENUMERATE = 2
    EXPLOIT = 3
    VERIFY = 4
    REPORT = 5


class ObjectiveStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    DONE = "DONE"


@dataclass
class Objective:
    description: str
    phase: Phase
    agent_type: str
    target: str
    params: dict = field(default_factory=dict)
    depends_on: list[int] = field(default_factory=list)
    # Assigned by Engagement.add_objective; 0 means "not yet added".
    id: int = 0
    status: ObjectiveStatus = ObjectiveStatus.PENDING
    outcome: Outcome | None = None
    attempts: int = 0
    result_summary: str = ""


@dataclass
class Engagement:
    target: str
    objectives: list[Objective] = field(default_factory=list)
    flag: str | None = None
    _id_counter: int = 0

    def add_objective(self, obj: Objective) -> Objective:
        self._id_counter += 1
        obj.id = self._id_counter
        self.objectives.append(obj)
        return obj

    def next_pending(self) -> Objective | None:
        """Lowest-phase pending objective whose dependencies are satisfied."""
        ready = [
            o
            for o in self.objectives
            if o.status == ObjectiveStatus.PENDING and self._deps_met(o)
        ]
        if not ready:
            return None
        ready.sort(key=lambda o: (int(o.phase), o.id))
        return ready[0]

    def _deps_met(self, obj: Objective) -> bool:
        done = {o.id for o in self.objectives if o.status == ObjectiveStatus.DONE}
        return all(dep in done for dep in obj.depends_on)

    def is_complete(self) -> bool:
        return all(o.status == ObjectiveStatus.DONE for o in self.objectives)


def default_plan(target: str) -> Engagement:
    """A static skeleton plan for a single scoped web target (e.g. DVWA).

    Recon runs first and may append new, more specific objectives at runtime;
    the later phases confirm and report. Agent types map to registry keys the
    orchestrator dispatches on.
    """
    eng = Engagement(target=target)
    eng.add_objective(
        Objective(
            description="Map the target: reachable endpoints, forms, and technologies.",
            phase=Phase.RECON,
            agent_type="recon",
            target=target,
        )
    )
    eng.add_objective(
        Objective(
            description="Enumerate candidate test points discovered during recon.",
            phase=Phase.ENUMERATE,
            agent_type="recon",
            target=target,
        )
    )
    eng.add_objective(
        Objective(
            description="Pursue the primary objective against the identified candidates.",
            phase=Phase.EXPLOIT,
            agent_type="exploit",
            target=target,
        )
    )
    eng.add_objective(
        Objective(
            description="Confirm the result and capture evidence / flag.",
            phase=Phase.VERIFY,
            agent_type="verifier",
            target=target,
        )
    )
    eng.add_objective(
        Objective(
            description="Compile the engagement report from stored findings.",
            phase=Phase.REPORT,
            agent_type="reporter",
            target=target,
        )
    )
    return eng
