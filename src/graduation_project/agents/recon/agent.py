"""Recon agent: passive and active information gathering only.

Scope: maps what is reachable on the in-scope target (ports, services,
versions, exposed paths, missing security headers) and records it as
structured Findings for the Exploit agent and the final report to consume.
It never attempts exploitation — that is a different agent's job.

Outcome mapping onto this project's benchmark-oriented vocabulary
(graduation_project.core.outcomes.Outcome), since Recon never produces a
flag and therefore can never report SOLVED:
  - FAILED   : recon ran to completion (even if some sub-tool was skipped
               or came back empty); this is Recon's normal "done" outcome.
  - BLOCKED  : recon could not run at all (no tool available, target
               unreachable, or out of scope) — retryable by the orchestrator.
  - ERROR    : an unexpected exception, not a tool's own reported failure.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

from graduation_project.agents.recon.header_check import (
    ToolUnavailable as HeaderToolUnavailable,
    run_header_check,
)
from graduation_project.agents.recon.llm_planner import LLMUnavailable, suggest_probes
from graduation_project.agents.recon.nikto_scan import (
    ToolUnavailable as NiktoUnavailable,
    run_nikto_scan,
)
from graduation_project.agents.recon.nmap_scan import (
    ToolUnavailable as NmapUnavailable,
    run_nmap_scan,
)
from graduation_project.agents.recon.probe_fetch import (
    ToolUnavailable as ProbeFetchUnavailable,
    fetch_path,
)
from graduation_project.config import GEMINI_API_KEY
from graduation_project.core.contracts import AgentResult, Finding, Task
from graduation_project.core.outcomes import Outcome
from graduation_project.core.roe import RoEViolation, host_of


@dataclass
class _StepOutcome:
    name: str
    ran: bool
    note: str = ""


class ReconAgent:
    agent_type = "recon"

    def run(self, task: Task) -> AgentResult:
        # Defensive scope check even though the orchestrator enforces this
        # before dispatch — an agent should never trust a target it wasn't
        # independently able to validate.
        if task.roe is not None:
            try:
                task.roe.enforce(task.target)
            except RoEViolation as exc:
                return AgentResult(Outcome.BLOCKED, str(exc))

        host = host_of(task.target)
        if host is None:
            return AgentResult(
                Outcome.BLOCKED, f"Could not derive a host from target {task.target!r}"
            )

        findings: list[Finding] = []
        steps: list[_StepOutcome] = []

        steps.append(self._run_nmap(task, host, findings))
        steps.append(self._run_nikto(task, findings))
        steps.append(self._run_headers(task, findings))
        steps.append(self._run_llm_planner(task, findings))

        ran_steps = [s for s in steps if s.ran]
        if not ran_steps:
            reasons = "; ".join(f"{s.name}: {s.note}" for s in steps)
            return AgentResult(Outcome.BLOCKED, f"No recon step could run ({reasons})")

        summary_bits = [f"{s.name} {'ok' if s.ran else 'skipped: ' + s.note}" for s in steps]
        summary = (
            f"Recon on {task.target} complete — {len(findings)} finding(s). "
            + "; ".join(summary_bits)
        )
        return AgentResult(Outcome.FAILED, summary, findings=findings)

    # -- individual scan steps -------------------------------------------------

    def _run_nmap(self, task: Task, host: str, findings: list[Finding]) -> _StepOutcome:
        try:
            ports = run_nmap_scan(host)
        except NmapUnavailable as exc:
            return _StepOutcome("nmap", ran=False, note=str(exc))
        except Exception as exc:  # tool ran but failed / timed out / bad output
            return _StepOutcome("nmap", ran=False, note=f"scan failed: {exc}")

        for p in ports:
            findings.append(
                Finding(
                    objective_id=task.objective_id,
                    agent_type=self.agent_type,
                    target=task.target,
                    title=f"Open port {p.port}/{p.protocol} ({p.service or 'unknown'})",
                    detail=p.as_text(),
                    severity="info",
                    data={
                        "port": p.port,
                        "protocol": p.protocol,
                        "service": p.service,
                        "product": p.product,
                        "version": p.version,
                        "extrainfo": p.extrainfo,
                        "source": "nmap",
                    },
                )
            )
        return _StepOutcome("nmap", ran=True, note=f"{len(ports)} open port(s)")

    def _run_nikto(self, task: Task, findings: list[Finding]) -> _StepOutcome:
        try:
            items = run_nikto_scan(task.target)
        except NiktoUnavailable as exc:
            return _StepOutcome("nikto", ran=False, note=str(exc))
        except Exception as exc:
            return _StepOutcome("nikto", ran=False, note=f"scan failed: {exc}")

        for item in items:
            if not item.message:
                continue
            findings.append(
                Finding(
                    objective_id=task.objective_id,
                    agent_type=self.agent_type,
                    target=task.target,
                    title=f"nikto: {item.message[:80]}",
                    detail=item.message,
                    severity="info",
                    data={
                        "nikto_id": item.item_id,
                        "url": item.url,
                        "source": "nikto",
                    },
                )
            )
        return _StepOutcome("nikto", ran=True, note=f"{len(items)} item(s)")

    def _run_headers(self, task: Task, findings: list[Finding]) -> _StepOutcome:
        try:
            result = run_header_check(task.target)
        except HeaderToolUnavailable as exc:
            return _StepOutcome("headers", ran=False, note=str(exc))
        except Exception as exc:
            return _StepOutcome("headers", ran=False, note=f"check failed: {exc}")

        if result.missing_security_headers:
            findings.append(
                Finding(
                    objective_id=task.objective_id,
                    agent_type=self.agent_type,
                    target=task.target,
                    title="Missing security headers",
                    detail=", ".join(result.missing_security_headers),
                    severity="info",
                    data={
                        "missing_headers": result.missing_security_headers,
                        "source": "header_check",
                    },
                )
            )
        for name, value in result.banners.items():
            findings.append(
                Finding(
                    objective_id=task.objective_id,
                    agent_type=self.agent_type,
                    target=task.target,
                    title=f"Version-revealing header: {name}",
                    detail=f"{name}: {value}",
                    severity="info",
                    data={"header": name, "value": value, "source": "header_check"},
                )
            )
        return _StepOutcome(
            "headers", ran=True, note=f"{len(result.missing_security_headers)} missing, {len(result.banners)} banner(s)"
        )

    def _run_llm_planner(self, task: Task, findings: list[Finding]) -> _StepOutcome:
        """The hybrid 'AI' layer: Gemini reads what the deterministic tools
        already found and suggests a few extra passive paths worth a GET
        request (e.g. /robots.txt, /.git/config). Still pure recon — the
        model is never given the ability to submit forms or run exploits,
        only to name paths, and every suggestion is re-validated and
        scope-checked here before anything is fetched.
        """
        if not findings:
            return _StepOutcome("llm_planner", ran=False, note="no findings yet to reason over")

        evidence_summary = "\n".join(f"- {f.title}: {f.detail}" for f in findings)
        try:
            probes = suggest_probes(evidence_summary, GEMINI_API_KEY)
        except LLMUnavailable as exc:
            return _StepOutcome("llm_planner", ran=False, note=str(exc))

        if not probes:
            return _StepOutcome("llm_planner", ran=True, note="no additional paths suggested")

        checked = 0
        for probe in probes:
            url = urljoin(task.target, probe.path)
            # Defense in depth: re-validate scope even though the path was
            # already filtered to be relative — urljoin could still resolve
            # somewhere unexpected on a malformed target.
            if task.roe is not None and not task.roe.is_in_scope(url):
                continue
            try:
                status, snippet = fetch_path(url)
            except (ProbeFetchUnavailable, RuntimeError) as exc:
                findings.append(
                    Finding(
                        objective_id=task.objective_id,
                        agent_type=self.agent_type,
                        target=task.target,
                        title=f"LLM-suggested probe failed: {probe.path}",
                        detail=str(exc),
                        severity="info",
                        data={"path": probe.path, "source": "llm_planner", "error": str(exc)},
                    )
                )
                continue
            checked += 1
            if status and status != 404:
                findings.append(
                    Finding(
                        objective_id=task.objective_id,
                        agent_type=self.agent_type,
                        target=task.target,
                        title=f"LLM-suggested path responded: {probe.path} ({status})",
                        detail=snippet,
                        severity="info",
                        data={"path": probe.path, "status": status, "source": "llm_planner"},
                    )
                )
        return _StepOutcome("llm_planner", ran=True, note=f"{checked} path(s) checked")
