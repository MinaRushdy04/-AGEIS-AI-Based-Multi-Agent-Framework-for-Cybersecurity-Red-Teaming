"""Verifier agent: independently re-checks Exploit findings before they
count, per spec:
    1. Reproduce the result independently using the recorded payload.
    2. Confirm the evidence (response content/timing/status) actually
       matches the claimed vulnerability.
    3. Mark CONFIRMED or REJECTED with a one-line reason.
Only CONFIRMED findings move forward to the Reporter.

What's implemented here vs. what's a stub, and why:

  - Step 1 (actually resending the payload to the target) is a STUB
    (`_reproduce`). Resending an injection/attack payload and interpreting
    the response is itself performing exploitation — the same category of
    action the Exploit agent's technique handlers do — so it belongs with
    whoever writes those handlers. Don't duplicate that HTTP-sending code
    here: have `_reproduce` call the exact same sending function the
    Exploit agent already wrote for that technique.

  - Steps 2 and 3 (comparing the reproduced evidence against what was
    claimed, and deciding CONFIRMED/REJECTED with a reason) ARE fully
    implemented below. This is generic evidence-matching, not technique
    logic: it only compares values the Exploit agent already supplied
    (a `success_indicator` pattern and/or a timing threshold) against
    what `_reproduce` returns — it has no idea what SQLi or XSS even are.

Expected shape of an Exploit Finding for this Verifier to work with
(document this for whoever implements the Exploit technique handlers):
    Finding(
        agent_type="exploit",
        severity=...,
        data={
            "payload": "<exact payload to resend>",
            "response": "<originally observed response (for reference)>",
            "confirmed": True | False,       # Exploit's own initial verdict
            "flag": "<optional flag/token>",

            # At least one of these two must be set for Verifier to be able
            # to judge a *reproduced* response — without one, the finding
            # falls back to a weaker "evidence present" check, clearly
            # labeled as such, never silently treated as independently
            # confirmed.
            "success_indicator": "<substring/regex expected on success>",
            "expected_min_response_time": <seconds, for time-based blind checks>,
        },
    )
"""

from __future__ import annotations

import re
import time

from graduation_project.core.contracts import AgentResult, Finding, Task
from graduation_project.core.outcomes import Outcome
from graduation_project.core.roe import RoEViolation


class ReproductionUnavailable(Exception):
    """Raised by `_reproduce` until someone wires it to real payload-resend
    code (reusing the Exploit agent's own sender for that technique)."""


class VerifierAgent:
    agent_type = "verifier"

    def run(self, task: Task) -> AgentResult:
        if task.roe is not None:
            try:
                task.roe.enforce(task.target)
            except RoEViolation as exc:
                return AgentResult(Outcome.BLOCKED, str(exc))

        exploit_findings = [f for f in task.context if f.agent_type == "exploit"]
        if not exploit_findings:
            return AgentResult(
                Outcome.NEEDS_INFO,
                "No Exploit findings available yet for this target — nothing to verify.",
            )

        confirmed: list[Finding] = []
        verdicts: list[str] = []

        for finding in exploit_findings:
            verdict, reason, repro_response = self._verify(task, finding)
            verdicts.append(f"{finding.title!r}: {verdict} ({reason})")
            if verdict == "CONFIRMED":
                confirmed.append(
                    Finding(
                        objective_id=task.objective_id,
                        agent_type=self.agent_type,
                        target=task.target,
                        title=f"Verified: {finding.title}",
                        detail=reason,
                        severity=finding.severity,
                        data={
                            "source_finding": finding.title,
                            "payload": finding.data.get("payload"),
                            "original_response": finding.data.get("response"),
                            "reproduced_response": repro_response,
                            "verdict": "CONFIRMED",
                            "reason": reason,
                        },
                    )
                )

        if not confirmed:
            return AgentResult(
                Outcome.FAILED,
                f"{len(exploit_findings)} finding(s) reviewed, 0 confirmed. "
                + "; ".join(verdicts),
            )

        flag = self._extract_flag(confirmed, exploit_findings)
        return AgentResult(
            Outcome.SOLVED,
            f"{len(confirmed)} of {len(exploit_findings)} finding(s) CONFIRMED. "
            + "; ".join(verdicts),
            findings=confirmed,
            flag=flag,
        )

    # -- step 1: reproduction (STUB — see module docstring) ---------------------

    def _reproduce(self, task: Task, finding: Finding) -> str:
        """Resend `finding.data['payload']` to the target and return the fresh
        response text — by REUSING the Exploit agent's own sender, not new code.

        The Exploit agent exposes a single sending entry point,
        `resend_payload(target, source, parameter, payload)`. We hand it the
        values the Exploit finding recorded (`source`, `parameter`, `payload`)
        so the identical probe is re-issued against the same endpoint. Still
        non-destructive — it only re-runs a detection probe.
        """
        from graduation_project.agents.exploit.agent import resend_payload

        source = finding.data.get("source")
        payload = finding.data.get("payload")
        parameter = finding.data.get("parameter")
        if not source:
            raise ReproductionUnavailable(
                "finding has no 'source' tag saying which exploit probe to re-send"
            )
        if not payload or not str(payload).strip():
            raise ReproductionUnavailable("finding has no 'payload' to re-send")

        try:
            return resend_payload(task.target, source, parameter, payload)
        except Exception as exc:  # network/tooling failure during reproduction
            raise ReproductionUnavailable(f"re-send failed: {exc}") from exc

    # -- steps 2 & 3: compare evidence, decide CONFIRMED/REJECTED ---------------

    def _verify(self, task: Task, finding: Finding) -> tuple[str, str, str | None]:
        """Returns (verdict, one-line reason, reproduced_response_or_None)."""
        if not finding.data.get("confirmed"):
            return "REJECTED", "Exploit agent did not mark this as confirmed", None

        payload = finding.data.get("payload")
        if not payload or not str(payload).strip():
            return "REJECTED", "no payload recorded to reproduce", None

        # Time the reproduction — needed for time-based blind checks below.
        start = time.perf_counter()
        try:
            fresh_response = self._reproduce(task, finding)
        except ReproductionUnavailable as exc:
            # Fall back to the weaker check: evidence was at least recorded
            # completely, even though we could not independently re-run it.
            # Never call this CONFIRMED — it's a distinct, weaker verdict.
            response = finding.data.get("response")
            if response and str(response).strip():
                return (
                    "REJECTED",
                    f"reproduction not available ({exc}); original evidence present "
                    "but not independently re-checked",
                    None,
                )
            return "REJECTED", f"reproduction not available ({exc}); no evidence either", None
        elapsed = time.perf_counter() - start

        # Time-based blind: the Exploit agent supplies expected_min_response_time
        # instead of a content signature; confirm by the reproduction's RESPONSE
        # TIME (a slow response = the injected SLEEP really executed).
        min_time = finding.data.get("expected_min_response_time")
        if min_time is not None:
            if elapsed >= float(min_time):
                return ("CONFIRMED",
                        f"reproduced response delayed {elapsed:.1f}s (>= {min_time}s expected)",
                        fresh_response)
            return ("REJECTED",
                    f"reproduced response was fast ({elapsed:.1f}s < {min_time}s expected)",
                    fresh_response)

        reason = self._compare(finding, fresh_response)
        if reason is None:
            return "CONFIRMED", "reproduced response matched the claimed success indicator", fresh_response
        return "REJECTED", reason, fresh_response

    def _compare(self, finding: Finding, fresh_response: str) -> str | None:
        """Generic evidence matching — no technique knowledge. Returns a
        rejection reason, or None if the reproduced evidence matches what
        the Exploit agent claimed would indicate success.
        """
        indicator = finding.data.get("success_indicator")
        if indicator:
            try:
                matched = bool(re.search(indicator, fresh_response))
            except re.error:
                matched = indicator in fresh_response
            if not matched:
                return f"reproduced response did not contain/match success_indicator {indicator!r}"
            return None

        # No success_indicator supplied — nothing generic left to check.
        return "no success_indicator provided by Exploit agent to compare the reproduction against"

    def _extract_flag(self, confirmed: list[Finding], all_exploit: list[Finding]) -> str | None:
        for f in confirmed:
            # confirmed Finding's data references the original finding's title;
            # pull the flag from whichever original exploit finding it came from.
            match = next((e for e in all_exploit if e.title == f.data.get("source_finding")), None)
            if match and match.data.get("flag"):
                return str(match.data["flag"])
        return None
