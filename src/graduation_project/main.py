"""Entry point: build an engagement and run the orchestrator.

With no specialist agents registered yet, every objective resolves to BLOCKED
("no agent registered") — which still exercises the full engine: scheduling,
scope enforcement, retry/budget, and the persistent run log. Register the real
agents (recon/exploit/verifier/reporter) as they are built.
"""

from graduation_project.core.engagement import default_plan
from graduation_project.core.orchestrator import Budget, Orchestrator
from graduation_project.core.roe import RulesOfEngagement
from graduation_project.core.store import Store

TARGET = "http://dvwa"


def main():
    engagement = default_plan(TARGET)
    roe = RulesOfEngagement.for_target(TARGET)
    store = Store("runs/engagement.jsonl")
    orch = Orchestrator(engagement, roe, store, Budget())

    # Specialist agents register here once built, e.g.:
    #   from graduation_project.agents.recon.agent import ReconAgent
    #   orch.register_agent(ReconAgent())

    summary = orch.run()

    print(f"Target : {summary['target']}")
    print(f"Flag   : {summary['flag']}")
    print(f"Steps  : {summary['steps']}")
    print("Objectives:")
    for o in summary["objectives"]:
        print(
            f"  [{o['phase']:<9}] {o['agent']:<9} "
            f"{o['status']:<11} {o['outcome']}"
        )


if __name__ == "__main__":
    main()
