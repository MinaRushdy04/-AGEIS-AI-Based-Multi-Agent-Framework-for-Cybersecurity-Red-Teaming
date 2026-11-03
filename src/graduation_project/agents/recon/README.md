# Recon

Recon's implementation will be supplied later. This folder reserves its module
boundary; it does not replace or simulate that implementation.

Place recon's implementation and agent-specific files here when integrating it:

- `agent.py`: public factory / runner or the existing recon implementation.
- `adapter.py`: translate the shared task/context into recon's real API and
  normalize its output into the shared result contract.
- `schemas.py`: recon-specific observations and inventory.
- `prompts.py`: recon instructions.
- `tools.py`: recon tool wrappers using the injected sandbox interface.

Adapt these filenames to the real implementation rather than splitting working
code mechanically. Preserve the public task/result boundary.

Recon owns assigned observations, evidence artifacts and coverage gaps. It must
not import orchestrator internals, mutate the overall run state, or expand the
trusted scope. Return partial work, negative results and blockers explicitly.
