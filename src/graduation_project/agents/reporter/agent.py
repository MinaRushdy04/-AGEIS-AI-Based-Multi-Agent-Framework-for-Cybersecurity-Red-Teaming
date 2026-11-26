"""Reporter agent: turns CONFIRMED Verifier findings into the project's
Step-9 report, following the schema in `core/report_schema.py` (that module's
own docstring says it "defines ... the final report schema the Reporter
agent must follow" — this agent builds exactly that `ReportFinding` object
for every confirmed vulnerability, not an ad-hoc shape of its own).

Per spec, the Reporter only ever processes CONFIRMED findings — it never
reports a raw Exploit claim that Verifier rejected or never reached. For
each one it fills:

    1. Vulnerability name + exact location (URL/parameter)
    2. Payload/technique used to confirm it
    3. Plain-language risk explanation
    4. Severity (Low/Medium/High/Critical)
    5. Suggested remediation

...written so both a technical reviewer and a non-technical stakeholder can
use it: every `ReportFinding.impact` is the plain-language version, while
`description`/`cwe`/`mitre`/`evidence`/`steps_to_reproduce` carry the
technical detail. The whole write-up opens with a short executive summary.

This agent does no probing of its own — it only reads the Finding objects
Exploit and Verifier already produced, and the verification bookkeeping
Verifier already did (RulesOfEngagement's host check still runs first, for
consistency with every other agent, but there is nothing left here to touch
on the wire). Every `ReportFinding` is run through `report_schema.validate_
finding()` before being included, and any problems it flags are carried
along as `validation_issues` rather than silently dropped or silently
"fixed" — this agent trusts the schema's own rules over its own formatting.

The remediation advice below is standard, publicly documented defensive
guidance (OWASP-level: use parameterized queries, validate/allow-list file
paths, encode output, rate-limit auth) — generic fix guidance, not
exploitation detail.
"""

from __future__ import annotations

from graduation_project.core.contracts import AgentResult, Finding, Task
from graduation_project.core.outcomes import Outcome
from graduation_project.core.report_schema import (
    Confidence,
    Evidence,
    RemediationPriority,
    ReportFinding,
    Severity,
    validate_finding,
)
from graduation_project.core.roe import RoEViolation

# Keyed by the Exploit agent's `data["source"]` tag — lines up exactly with
# _probe_url()/resend_payload() in agents/exploit/agent.py and with
# core/attack_map.py's ATTACK_MAP keys, so every technique the Exploit agent
# can actually produce has an entry here (including the time-based blind
# SQLi path, which uses expected_min_response_time instead of a content
# match — see verifier/agent.py's `_verify`).
_VULN_INFO = {
    "sqli": {
        "name": "SQL Injection",
        "impact_clause": "allows unauthorized access to the application's database",
        "cwe": ["CWE-89"],
        "plain_risk": (
            "An attacker can slip extra commands into a database query through "
            "this input field. That can let them read data they should not see "
            "(other users' records, password hashes), or in some cases change "
            "or delete data."
        ),
        "remediation": (
            "Use parameterized queries / prepared statements for every database "
            "call — never build SQL by concatenating user input into a string. "
            "Pair this with least-privilege database accounts (the web app's DB "
            "user should not be able to read tables it has no business touching) "
            "and input validation as a secondary layer, not the primary defense."
        ),
    },
    "lfi": {
        "name": "Local File Inclusion",
        "impact_clause": "allows disclosure of files on the server's filesystem",
        "cwe": ["CWE-98"],
        "plain_risk": (
            "An attacker can make the server open files it was never meant to "
            "serve — for example configuration files, source code, or other "
            "sensitive files on the server's disk — by manipulating a "
            "file/page parameter."
        ),
        "remediation": (
            "Never pass user-supplied input directly into a filesystem path. "
            "Use a fixed allow-list of permitted page/file names instead of "
            "building a path from the request, and disable dynamic file "
            "inclusion of remote/user-controlled paths at the language/runtime "
            "level where applicable."
        ),
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "impact_clause": "allows session hijacking and page content manipulation via script injection",
        "cwe": ["CWE-79"],
        "plain_risk": (
            "An attacker can get their own script to run in another user's "
            "browser when that user views the page. That script can steal "
            "session cookies, impersonate the victim, or quietly change what "
            "the page shows them."
        ),
        "remediation": (
            "Encode all untrusted input for the context it is rendered in "
            "(HTML-escape for HTML bodies, attribute-escape for attributes, "
            "JS-escape for inline scripts) — most modern templating engines do "
            "this by default, so the usual root cause is a manual/unescaped "
            "output. Add a Content-Security-Policy header as defense-in-depth."
        ),
    },
    "brute": {
        "name": "Weak Authentication / Brute-Force-able Login",
        "impact_clause": "allows account takeover via unlimited password guessing",
        "cwe": ["CWE-307"],
        "plain_risk": (
            "An attacker can keep guessing usernames and passwords with no "
            "limit, because the login page never slows down or locks out "
            "repeated failed attempts. Given enough time, a weak or common "
            "password will eventually be found this way."
        ),
        "remediation": (
            "Add account lockout or exponential rate-limiting after a handful "
            "of failed attempts, plus a CAPTCHA for repeated failures. "
            "Enforce a minimum password strength policy and offer (or require) "
            "multi-factor authentication for any account with elevated access."
        ),
    },
}
_VULN_INFO["sqlmap"] = _VULN_INFO["sqli"]
_VULN_INFO["hydra"] = _VULN_INFO["brute"]
_VULN_INFO["sqli_blind"] = {
    **_VULN_INFO["sqli"],
    "name": "Blind SQL Injection (time-based)",
    "impact_clause": "allows unauthorized database access, extractable one bit at a time via response timing",
}

_GENERIC_VULN_INFO = {
    "name": "Confirmed Vulnerability",
    "impact_clause": "allows unauthorized behavior confirmed by independent reproduction",
    "cwe": [],
    "plain_risk": (
        "This was independently re-tested and the evidence matched what was "
        "originally claimed, but this report generator does not have a "
        "specific plain-language writeup for this technique category yet."
    ),
    "remediation": (
        "Review the technical detail below with the engineer who added this "
        "finding type, and treat the CWE/MITRE references as the starting "
        "point for the correct fix."
    ),
}

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFORMATIONAL,
}
_REMEDIATION_PRIORITY = {
    Severity.CRITICAL: RemediationPriority.IMMEDIATE,
    Severity.HIGH: RemediationPriority.IMMEDIATE,
    Severity.MEDIUM: RemediationPriority.SHORT_TERM,
    Severity.LOW: RemediationPriority.LONG_TERM,
    Severity.INFORMATIONAL: RemediationPriority.LONG_TERM,
}


class ReporterAgent:
    agent_type = "reporter"

    def __init__(self) -> None:
        # Reset per instance (and see `run`, which resets per call too) so
        # validation warnings from one run/target never leak into another's
        # report — the orchestrator can call `run` more than once.
        self._last_issues: dict[str, list[str]] = {}

    def run(self, task: Task) -> AgentResult:
        self._last_issues = {}
        if task.roe is not None:
            try:
                task.roe.enforce(task.target)
            except RoEViolation as exc:
                return AgentResult(Outcome.BLOCKED, str(exc))

        verifier_findings = [f for f in task.context if f.agent_type == "verifier"]
        confirmed = [f for f in verifier_findings if f.data.get("verdict") == "CONFIRMED"]

        if not verifier_findings:
            return AgentResult(
                Outcome.NEEDS_INFO,
                "No Verifier findings yet for this target — nothing to report.",
            )
        if not confirmed:
            return AgentResult(
                Outcome.FAILED,
                f"{len(verifier_findings)} Verifier finding(s) reviewed, "
                "0 CONFIRMED — nothing meets the bar to report.",
            )

        exploit_by_title = {f.title: f for f in task.context if f.agent_type == "exploit"}
        report_findings = [
            self._build_report_finding(i, vf, exploit_by_title.get(vf.data.get("source_finding")), task.target)
            for i, vf in enumerate(confirmed, start=1)
        ]

        report_markdown = self._render_markdown(task.target, report_findings)
        top_severity = max(
            (rf.severity for rf in report_findings),
            key=lambda s: _SEVERITY_RANK[s],
            default=Severity.LOW,
        )

        any_issues = any(rf.id in self._last_issues for rf in report_findings)

        result_finding = Finding(
            objective_id=task.objective_id,
            agent_type=self.agent_type,
            target=task.target,
            title=f"Penetration Test Report — {len(report_findings)} confirmed finding(s)",
            detail=f"{len(report_findings)} confirmed vulnerability(ies) written up; "
            f"highest severity {top_severity.value}.",
            severity=top_severity.value,
            data={
                "findings": [self._finding_to_dict(rf) for rf in report_findings],
                "validation_issues": self._last_issues,
                "report_markdown": report_markdown,
            },
        )

        return AgentResult(
            Outcome.SOLVED,
            f"Report generated for {len(report_findings)} confirmed finding(s) "
            f"(highest severity: {top_severity.value})."
            + (" Some findings have schema validation warnings — see validation_issues."
               if any_issues else ""),
            findings=[result_finding],
            raw={"report_markdown": report_markdown},
        )

    # -- building one ReportFinding from a CONFIRMED Verifier finding -------

    def _build_report_finding(
        self, index: int, verifier_finding: Finding, exploit_finding: Finding | None, target: str
    ) -> ReportFinding:
        source = (exploit_finding.data.get("source") if exploit_finding else None) or ""
        info = _VULN_INFO.get(source, _GENERIC_VULN_INFO)

        parameter = exploit_finding.data.get("parameter") if exploit_finding else None
        endpoint = (exploit_finding.data.get("endpoint") if exploit_finding else None) or target
        affected_component = f"'{parameter}' parameter" if parameter else "(parameter not recorded)"

        payload = verifier_finding.data.get("payload") or (
            exploit_finding.data.get("payload") if exploit_finding else None
        )
        raw_severity = (exploit_finding.severity if exploit_finding else verifier_finding.severity) or "low"
        severity = _SEVERITY_MAP.get(raw_severity.lower(), Severity.LOW)

        mitre = (exploit_finding.data.get("mitre") if exploit_finding else None) or []
        cwe = (exploit_finding.data.get("cwe") if exploit_finding else None)
        cwe_list = [cwe] if isinstance(cwe, str) else (cwe or info["cwe"])

        # Evidence: carry over whatever Exploit recorded, plus the Verifier's
        # own independent reproduction as a second, distinct evidence item.
        evidence: list[Evidence] = []
        for ev in (exploit_finding.data.get("evidence") if exploit_finding else None) or []:
            evidence.append(Evidence(
                type="http-request",
                path="",
                description=f"{ev.get('note', '')} (payload: {ev.get('payload', '')})".strip(),
            ))
        if verifier_finding.data.get("reproduced_response") is not None:
            evidence.append(Evidence(
                type="http-request",
                path="",
                description=(
                    "Independent reproduction by the Verifier agent re-sent the "
                    "same recorded payload and the response matched the claimed "
                    "success indicator."
                ),
            ))

        # Confidence: Exploit's own methods, PLUS the Verifier's independent
        # reproduction counts as a second, distinct verification method — it
        # is only ever CONFIRMED (reaching this agent at all) after Verifier
        # re-sent the payload itself and matched the evidence, never from
        # trusting Exploit's claim alone (see verifier/agent.py `_verify`).
        methods = list((exploit_finding.data.get("methods") if exploit_finding else None) or [])
        if exploit_finding and exploit_finding.data.get("tool"):
            methods.append(exploit_finding.data["tool"])
        if not methods and source:
            methods.append(source)
        methods.append("verifier-independent-reproduction")
        confidence = Confidence.VERIFIED if len(set(methods)) >= 2 else Confidence.PROBABLE

        steps = []
        if endpoint:
            steps.append(f"Authenticate to the application and navigate to {endpoint}.")
        if payload:
            target_desc = f"the '{parameter}' parameter" if parameter else "the vulnerable input"
            steps.append(f"Submit the recorded payload ({payload!r}) via {target_desc}.")
        steps.append(
            "Observe the response matching the confirmed success indicator "
            "(see Evidence) — independently reproduced by the Verifier agent."
        )

        rf = ReportFinding(
            id=f"FIND-{index:03d}",
            title=f"{info['name']} in {endpoint} {info['impact_clause']}",
            severity=severity,
            affected_target=target,
            description=verifier_finding.data.get("reason") or verifier_finding.detail or "",
            cwe=cwe_list,
            mitre=mitre,
            affected_component=affected_component,
            steps_to_reproduce=steps,
            negative_control=(exploit_finding.data.get("negative_control") if exploit_finding else "") or "",
            impact=info["plain_risk"],
            evidence=evidence,
            confidence=confidence,
            verified_methods=sorted(set(methods)),
            remediation=info["remediation"],
            remediation_priority=_REMEDIATION_PRIORITY[severity],
            agent=f"exploit/{source or 'unknown'}+verifier",
        )

        issues = validate_finding(rf)
        if issues:
            self._last_issues[rf.id] = issues
        return rf

    @staticmethod
    def _finding_to_dict(rf: ReportFinding) -> dict:
        return {
            "id": rf.id,
            "title": rf.title,
            "severity": rf.severity.value,
            "affected_target": rf.affected_target,
            "affected_component": rf.affected_component,
            "description": rf.description,
            "cwe": rf.cwe,
            "mitre": rf.mitre,
            "steps_to_reproduce": rf.steps_to_reproduce,
            "negative_control": rf.negative_control,
            "impact": rf.impact,
            "confidence": rf.confidence.value,
            "verified_methods": rf.verified_methods,
            "remediation": rf.remediation,
            "remediation_priority": rf.remediation_priority.value if rf.remediation_priority else None,
            "agent": rf.agent,
        }

    # -- rendering the full report ------------------------------------------

    def _render_markdown(self, target: str, findings: list[ReportFinding]) -> str:
        lines = [
            f"# Penetration Test Report — {target}",
            "",
            "## Executive Summary",
            "",
            (
                f"This engagement found **{len(findings)}** confirmed "
                f"vulnerabilit{'y' if len(findings) == 1 else 'ies'} in the "
                "tested application. Each one below was independently "
                "re-tested (not just reported once) before being included "
                "here, so these are not false positives from a single scan."
            ),
            "",
            "| # | Vulnerability | Severity | Confidence |",
            "|---|---|---|---|",
        ]
        for rf in findings:
            lines.append(f"| {rf.id} | {rf.title.split(' in ')[0]} | {rf.severity.value.title()} | {rf.confidence.value} |")
        lines.append("")

        lines.append("## Findings")
        lines.append("")
        for rf in findings:
            lines += [
                f"### {rf.id}: {rf.title}",
                "",
                f"**Location:** `{rf.affected_target}` — {rf.affected_component}",
                "",
                f"**In plain terms:** {rf.impact}",
                "",
                "**Technical detail:**",
                f"- Severity: {rf.severity.value.title()} (confidence: {rf.confidence.value}, "
                f"verified via: {', '.join(rf.verified_methods)})",
            ]
            if rf.cwe:
                lines.append(f"- CWE: {', '.join(rf.cwe)}")
            if rf.mitre:
                lines.append(f"- MITRE ATT&CK: {', '.join(rf.mitre)}")
            if rf.negative_control:
                lines.append(f"- Negative control: {rf.negative_control}")
            lines.append(f"- Independent verification: {rf.description}")
            if rf.steps_to_reproduce:
                lines.append("- Reproduction steps:")
                for j, step in enumerate(rf.steps_to_reproduce, start=1):
                    lines.append(f"  {j}. {step}")
            if rf.evidence:
                lines.append("- Evidence:")
                for ev in rf.evidence:
                    lines.append(f"  - {ev.description}")
            issues = self._last_issues.get(rf.id)
            if issues:
                lines.append(f"- ⚠ Schema validation warnings: {'; '.join(issues)}")
            lines += [
                "",
                f"**Suggested remediation** ({rf.remediation_priority.value if rf.remediation_priority else 'n/a'} priority): "
                f"{rf.remediation}",
                "",
            ]
        return "\n".join(lines)


_SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFORMATIONAL: 0,
}
