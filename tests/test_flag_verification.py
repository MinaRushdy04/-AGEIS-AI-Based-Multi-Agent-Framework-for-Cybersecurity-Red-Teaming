import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from graduation_project.core.contracts import AgentResult
from graduation_project.core.engagement import Engagement, Objective, Phase
from graduation_project.core.orchestrator import Orchestrator
from graduation_project.core.outcomes import Outcome
from graduation_project.core.roe import RulesOfEngagement
from graduation_project.core.store import Store


class FlagVerificationTests(unittest.TestCase):
    def _run(self, candidate, evaluator=None, *, outcome=Outcome.FAILED):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        store = Store(Path(scratch.name) / "engagement.sqlite3")
        target = "http://lab"
        plan = Engagement(target)
        orch = Orchestrator(
            plan, RulesOfEngagement.for_target(target), store, flag_evaluator=evaluator
        )

        plan.add_objective(Objective("Find a flag", Phase.EXPLOIT, "exploit", target))
        plan.add_objective(Objective("Check evidence", Phase.VERIFY, "verifier", target))
        plan.add_objective(Objective("Summarize the run", Phase.REPORT, "reporter", target))
        exploit = Mock(agent_type="exploit")
        exploit.run.return_value = AgentResult(outcome, "Attempt finished", flag=candidate)
        verifier = Mock(agent_type="verifier")
        verifier.run.return_value = AgentResult(Outcome.SOLVED, "Reviewed the evidence")
        reporter = Mock(agent_type="reporter")
        reporter.run.return_value = AgentResult(Outcome.SOLVED, "Wrote the report")
        for agent in (exploit, verifier, reporter):
            orch.register_agent(agent)

        summary = orch.run()
        reporter.run.assert_called_once()
        events = store.events()
        self.assertEqual(events[-1]["kind"], "engagement_end")
        evaluations = [event["status"] for event in events if event["kind"] == "flag_evaluation"]
        return summary, verifier, events, evaluations

    def test_wrong_flag_from_failed_attempt_cannot_skip_verification(self):
        evaluator = Mock(return_value=False)
        summary, verifier, events, evaluations = self._run("wrong-flag", evaluator)

        evaluator.assert_called_once_with("wrong-flag")
        verifier.run.assert_called_once()
        self.assertIsNone(summary["flag"])
        self.assertFalse(events[-1]["flag"])
        self.assertEqual(evaluations, ["rejected"])
        self.assertNotIn("wrong-flag", str(events))

    def test_accepted_flag_skips_remaining_checks_and_still_reports(self):
        evaluator = Mock(return_value=True)
        summary, verifier, events, evaluations = self._run(
            "correct-flag", evaluator, outcome=Outcome.SOLVED
        )

        evaluator.assert_called_once_with("correct-flag")
        verifier.run.assert_not_called()
        self.assertEqual(summary["flag"], "correct-flag")
        self.assertTrue(events[-1]["flag"])
        self.assertEqual(evaluations, ["accepted"])

    def test_missing_or_broken_evaluator_leaves_run_unsolved(self):
        for evaluator, status in (
            (None, "unavailable"),
            (Mock(side_effect=RuntimeError("Evaluator unavailable")), "error"),
        ):
            with self.subTest(status=status):
                summary, verifier, events, evaluations = self._run(
                    "candidate-flag", evaluator, outcome=Outcome.SOLVED
                )

                verifier.run.assert_called_once()
                self.assertIsNone(summary["flag"])
                self.assertFalse(events[-1]["flag"])
                self.assertEqual(evaluations, [status])
