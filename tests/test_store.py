import sqlite3
import tempfile
import unittest
from pathlib import Path

from graduation_project.core.contracts import AgentResult, Finding, Task
from graduation_project.core.engagement import Engagement, Objective, Phase
from graduation_project.core.orchestrator import Orchestrator
from graduation_project.core.outcomes import Outcome
from graduation_project.core.roe import RulesOfEngagement
from graduation_project.core.store import Store


class StoreTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.path = Path(scratch.name) / "engagement.sqlite3"

    def test_orchestrator_passes_and_persists_recon_evidence(self):
        target = "http://lab"
        engagement = Engagement(target)
        recon = engagement.add_objective(Objective("Discover pages", Phase.RECON, "recon", target))
        engagement.add_objective(
            Objective("Check a page", Phase.EXPLOIT, "exploit", target, depends_on=[recon.id])
        )
        finding = Finding(recon.id, "recon", "http://lab/login", "Login page", "HTTP 200")
        received = []

        class Recon:
            agent_type = "recon"

            def run(self, task: Task) -> AgentResult:
                return AgentResult(Outcome.SOLVED, "Page discovered", [finding])

        class Exploit:
            agent_type = "exploit"

            def run(self, task: Task) -> AgentResult:
                received.extend(task.context)
                return AgentResult(Outcome.FAILED, "No vulnerability found")

        store = Store(self.path)
        orch = Orchestrator(engagement, RulesOfEngagement.for_target(target), store)
        orch.register_agent(Recon())
        orch.register_agent(Exploit())
        self.assertEqual(orch.run()["steps"], 2)
        self.assertEqual(received, [finding])

        reopened = Store(self.path, run_id=store.run_id)
        self.assertEqual(reopened.findings_for(target="http://LAB:80", objective_id=recon.id), [finding])
        self.assertEqual(reopened.findings_for(target="http://other"), [])
        self.assertEqual(reopened.findings_for(objective_id=recon.id + 1), [])
        self.assertEqual(
            [event["kind"] for event in reopened.events()],
            ["engagement_start", "dispatch", "finding", "result", "dispatch", "result", "engagement_end"],
        )
        self.assertEqual(reopened.events()[3]["attempt"], 1)

        new_run = Store(self.path)
        self.assertEqual(new_run.findings_for(target=target, objective_id=recon.id), [])
        self.assertEqual(new_run.events(), [])

    def test_failed_result_write_leaves_no_partial_findings(self):
        store = Store(self.path)
        valid = Finding(1, "recon", "http://lab", "Page", "HTTP 200")
        # A list can be JSON-encoded but cannot be bound as an SQLite column value.
        invalid = Finding([], "recon", "http://lab", "Invalid objective ID", "")
        result = AgentResult(Outcome.SOLVED, "Two findings", [valid, invalid])

        with self.assertRaises(sqlite3.ProgrammingError):
            store.record_result(1, 1, result)

        self.assertEqual(store.findings_for(), [])
        self.assertEqual(store.events(), [])
