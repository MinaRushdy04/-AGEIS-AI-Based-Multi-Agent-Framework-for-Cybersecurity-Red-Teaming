# Orchestrator

This package will own task creation, dispatch, lifecycle transitions, result
validation, bounded retries, cancellation, and evidence-linked run summaries.
It will receive agents and infrastructure adapters through dependency injection.

The [XBOW MVP specification](../../../../docs/orchestrator-mvp.md) defines the
controller loop, task/result contracts, scope enforcement, persistence and
benchmark success criteria. The [decision-model prompt](system_prompt.md) is a
design artifact awaiting runtime integration.

Implement these files as the first vertical slice grows:

- `agent.py`: public factory / runner and orchestrator assembly.
- `workflow.py`: sequential control flow and task lifecycle.
- `state.py`: private orchestration state.
- `system_prompt.md`: decision-model role instructions.
- `routing.py`: validate proposed decisions against registered capabilities.

Use shared contracts for task handoffs. Keep scope authority and state
transitions in application code; do not delegate them to model-generated prose.
Specialist tools remain with their owning agent.

The benchmark MVP coordinates Recon and Exploit; Verifier and Reporter can
begin as deterministic modules. Fake specialists can verify workflow behavior
before their real implementations arrive. This scaffold does not implement an
orchestrator or change the existing top-level `agent.py` placeholder.
