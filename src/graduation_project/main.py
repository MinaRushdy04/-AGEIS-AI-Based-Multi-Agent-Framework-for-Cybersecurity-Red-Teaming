"""Entry point: run the full orchestrated engagement against DVWA.

    python -m graduation_project.main

Wires together everything the other modules already provide:
  - the static 5-phase plan (core.engagement.default_plan)
  - scope, loaded from the single reviewed source of truth (plan/roe.json)
  - persistent SQLite storage for the run (core.store.Store)
  - the four real specialist agents (Recon, Exploit, Verifier, Reporter)
  - writing the Reporter's Markdown write-up to disk once the run finishes

Flag trust boundary: the Orchestrator never takes an agent's own "I found a
flag" claim at face value — every candidate goes through `flag_evaluator`
before it's accepted and the run fast-forwards to REPORT (see
core/orchestrator.py's `_evaluate_flag`). The Verifier agent already does the
real work of independently reproducing and matching evidence before it ever
sets `AgentResult.flag`, so by the time a candidate reaches this evaluator it
has already survived that check. This default evaluator just accepts any
non-empty candidate; replace it with real validation (e.g. comparing against
a known expected flag for the engagement) if/when the project defines one.
"""

from __future__ import annotations

from pathlib import Path

from graduation_project.agents.exploit import ExploitAgent
from graduation_project.agents.recon import ReconAgent
from graduation_project.agents.reporter import ReporterAgent
from graduation_project.agents.verifier import VerifierAgent
from graduation_project.core.engagement import default_plan
from graduation_project.core.orchestrator import Budget, Orchestrator
from graduation_project.core.roe import RulesOfEngagement
from graduation_project.core.store import Store

TARGET = "http://dvwa"
ROE_FILE = Path(__file__).resolve().parents[2] / "plan" / "roe.json"
STORE_PATH = Path(__file__).resolve().parents[2] / "runs" / "engagement.sqlite3"
REPORT_DIR = Path(__file__).resolve().parents[2] / "reports"


def accept_any_nonempty_flag(candidate: str) -> bool:
    """Placeholder flag_evaluator — see module docstring. Swap this out once
    the project has a real expected flag (or a stronger format check) to
    validate a candidate against, rather than trusting Verifier alone.
    """
    return bool(candidate and candidate.strip())


def main():
    engagement = default_plan(TARGET)
    roe = RulesOfEngagement.from_roe_file(ROE_FILE)
    store = Store(STORE_PATH)
    orch = Orchestrator(
        engagement, roe, store, Budget(), flag_evaluator=accept_any_nonempty_flag
    )

    orch.register_agent(ReconAgent())
    orch.register_agent(ExploitAgent())
    orch.register_agent(VerifierAgent())
    orch.register_agent(ReporterAgent())

    summary = orch.run()  # plain dict — see Orchestrator._summary()

    print(f"Target : {summary['target']}")
    print(f"Flag   : {summary['flag']}")
    print(f"Steps  : {summary['steps']}")
    print("Objectives:")
    for obj in summary["objectives"]:
        print(
            f"  [{obj['phase']:9}] {obj['agent']:9} "
            f"{obj['status']:11} {obj['outcome']} — {obj['summary']}"
        )

    _write_report_if_any(store)


def _write_report_if_any(store: Store) -> None:
    """The Reporter agent only returns its Markdown write-up inside the
    Finding it hands back to the orchestrator (agents never write files
    themselves — only the orchestrator/Store persist state). Pull it back
    out of the store here and save it next to the run, so the team gets an
    actual report file instead of having to read it out of the DB.
    """
    report_findings = [
        f for f in store.findings_for(target=TARGET) if f.agent_type == "reporter"
    ]
    if not report_findings:
        return
    markdown = report_findings[-1].data.get("report_markdown")
    if not markdown:
        return
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = REPORT_DIR / f"{store.run_id}.md"
    out_path.write_text(markdown, encoding="utf-8")
    print(f"\nReport written to: {out_path}")


if __name__ == "__main__":
    main()
