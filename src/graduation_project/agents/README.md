# Agent modules

Each agent owns a subfolder containing its implementation, prompts, local
schemas, and tool wrappers. The initial roles are `orchestrator` and `recon`.
Both folders currently contain package scaffolding and design notes only.

The application composition root will wire agents through shared contracts.
Agents must not import another agent's implementation or mutate its private
state. The orchestrator will receive an explicit registry of agent interfaces;
recon will return observations and evidence through an adapter.

Shared task/result contracts and adapter interfaces belong in `core` when they
are implemented. Model clients, storage and sandbox transport belong in
`infrastructure`. Keep agent-specific files in their agent folder.

See the [repository review and orchestrator design](../../../docs/architecture-review.md)
for the target layout, proposed contracts and first vertical slice.
