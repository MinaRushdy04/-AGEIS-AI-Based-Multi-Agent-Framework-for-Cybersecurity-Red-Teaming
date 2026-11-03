# -AGEIS-AI-Based-Multi-Agent-Framework-for-Cybersecurity-Red-Teaming
This serves as CEAI SUE Class of 27 Graduation Project, Prepared by a 3-man squad. Techstack and more details to be appended in the README

## Architecture

The project is organized as a modular monolith, with one subpackage per agent
under `src/graduation_project/agents/`. The orchestrator and recon folders are
currently package scaffolds; the runtime entrypoint remains the initial
placeholder.

See the [repository review and orchestrator design](docs/architecture-review.md)
for current findings, module boundaries, the proposed agent contract, and the
first vertical slice.

The [XBOW orchestrator MVP design](docs/orchestrator-mvp.md) defines the proposed
challenge-solving loop, role boundaries, scope controls, and evaluation contract.
