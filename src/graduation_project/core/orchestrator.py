"""The orchestrator: a deterministic scheduler that drives specialist agents.

Intentionally NOT an LLM. It owns the loop, scope enforcement, budget, and
result handling; all language-model work lives in the specialist agents it
dispatches to. This is what makes runs reproducible, cheap, and gradeable —
the properties an XBOW-style benchmark needs.

Loop, per step:
  1. Pick the next pending objective (phase-ordered, dependencies satisfied).
  2. Build a FRESH task with RoE + only the relevant prior findings.
  3. Enforce scope in code, then dispatch to the objective's agent.
  4. Record the outcome to persistent storage; retry transient failures.
  5. On flag capture, fast-forward past remaining attack phases to REPORT.
Stops when the budget is spent or no objective remains.
"""

from __future__ import annotations

from dataclasses import dataclass

from graduation_project.core.contracts import Agent, AgentResult, Task
from graduation_project.core.engagement import (
    Engagement,
    Objective,
    ObjectiveStatus,
    Phase,
)
from graduation_project.core.outcomes import RETRYABLE, Outcome
from graduation_project.core.roe import RoEViolation, RulesOfEngagement
from graduation_project.core.store import Store


@dataclass
class Budget:
    """Hard caps so an easy challenge can never loop forever or drain quota."""

    max_steps: int = 50
    max_attempts_per_objective: int = 2


class Orchestrator:
    def __init__(
        self,
        engagement: Engagement,
        roe: RulesOfEngagement,
        store: Store,
        budget: Budget | None = None,
    ):
        self.engagement = engagement
        self.roe = roe
        self.store = store
        self.budget = budget or Budget()
        self._agents: dict[str, Agent] = {}
        self._steps = 0

    # -- wiring ---------------------------------------------------------------

    def register_agent(self, agent: Agent) -> None:
        """Deterministic routing: objective.agent_type -> this registry."""
        self._agents[agent.agent_type] = agent

    # -- main loop ------------------------------------------------------------

    def run(self) -> dict:
        self.store.log_event(
            "engagement_start",
            target=self.engagement.target,
            objectives=len(self.engagement.objectives),
            scope=sorted(self.roe.allowed_hosts),
        )
        while not self._should_stop():
            obj = self.engagement.next_pending()
            if obj is None:
                break
            self._steps += 1
            self._execute(obj)
        return self._summary()

    def _should_stop(self) -> bool:
        if self._steps >= self.budget.max_steps:
            self.store.log_event("budget_exhausted", steps=self._steps)
            return True
        return False

    # -- per-objective execution ---------------------------------------------

    def _execute(self, obj: Objective) -> None:
        obj.status = ObjectiveStatus.IN_PROGRESS
        obj.attempts += 1
        task = self._build_task(obj)

        # Code-level scope control: runs BEFORE any agent touches the target.
        try:
            self.roe.enforce(task.target)
        except RoEViolation as exc:
            self.store.log_event(
                "roe_violation", objective_id=obj.id, target=task.target
            )
            self._record(obj, AgentResult(Outcome.BLOCKED, str(exc)))
            return

        agent = self._agents.get(obj.agent_type)
        if agent is None:
            self._record(
                obj,
                AgentResult(
                    Outcome.BLOCKED,
                    f"No agent registered for type {obj.agent_type!r}",
                ),
            )
            return

        self.store.log_event(
            "dispatch",
            objective_id=obj.id,
            agent=obj.agent_type,
            target=task.target,
            phase=obj.phase.name,
            attempt=obj.attempts,
        )
        try:
            result = agent.run(task)
        except Exception as exc:  # isolate agent crashes from the engine
            result = AgentResult(Outcome.ERROR, f"Agent raised: {exc!r}")
        self._record(obj, result)

    def _build_task(self, obj: Objective) -> Task:
        # Attach only the findings relevant to this target — selective context.
        context = self.store.findings_for(target=obj.target)
        return Task(
            objective_id=obj.id,
            agent_type=obj.agent_type,
            target=obj.target,
            description=obj.description,
            params=dict(obj.params),
            context=context,
            roe=self.roe,
        )

    def _record(self, obj: Objective, result: AgentResult) -> None:
        obj.outcome = result.outcome
        obj.result_summary = result.summary
        for finding in result.findings:
            self.store.add_finding(finding)
        if result.flag:
            self.engagement.flag = result.flag

        self.store.log_event(
            "result",
            objective_id=obj.id,
            outcome=result.outcome.value,
            summary=result.summary,
            flag=bool(result.flag),
        )

        # Retry policy: transient outcomes requeue until the budget is spent.
        if (
            result.outcome in RETRYABLE
            and obj.attempts < self.budget.max_attempts_per_objective
        ):
            obj.status = ObjectiveStatus.PENDING
        else:
            obj.status = ObjectiveStatus.DONE

        # Flag captured: skip remaining attack phases, go straight to REPORT.
        if self.engagement.flag is not None:
            self._skip_to_report()

    def _skip_to_report(self) -> None:
        for o in self.engagement.objectives:
            if o.status == ObjectiveStatus.PENDING and o.phase < Phase.REPORT:
                o.status = ObjectiveStatus.DONE
                o.result_summary = "skipped: flag already captured"
                self.store.log_event(
                    "skipped", objective_id=o.id, reason="flag_captured"
                )

    # -- reporting ------------------------------------------------------------

    def _summary(self) -> dict:
        self.store.log_event(
            "engagement_end", flag=bool(self.engagement.flag), steps=self._steps
        )
        return {
            "target": self.engagement.target,
            "flag": self.engagement.flag,
            "steps": self._steps,
            "objectives": [
                {
                    "id": o.id,
                    "phase": o.phase.name,
                    "agent": o.agent_type,
                    "status": o.status.value,
                    "outcome": o.outcome.value if o.outcome else None,
                    "summary": o.result_summary,
                }
                for o in self.engagement.objectives
            ],
        }
