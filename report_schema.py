"""Verification & reporting schema (Step 9).

Defines (a) how we confirm a finding is REAL — reproduction + a negative control,
plus a confidence level that drives verification requirements — and (b) the final
report schema the Reporter agent must follow (severity, CVSS, evidence, remediation).

This is a lightweight, web-focused version of the Decepticon reference schema
(`decepticon_core.types.engagement.Finding` + its finding-epistemics discipline):
CVSS-aligned severity bands, confidence that gates critical/high findings, ATT&CK
technique IDs (from Step 7), reproduction steps, a negative control to rule out
false positives, evidence, and PTES/CREST remediation priorities.

Kept as plain dataclasses to match this project's `core/contracts.py` style.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """CVSS-aligned severity bands (same bands as Decepticon)."""
    CRITICAL = "critical"            # CVSS 9.0-10.0
    HIGH = "high"                    # CVSS 7.0-8.9
    MEDIUM = "medium"                # CVSS 4.0-6.9
    LOW = "low"                      # CVSS 0.1-3.9
    INFORMATIONAL = "informational"  # CVSS 0.0 — observation only


class Confidence(str, Enum):
    """How sure we are a finding is real — drives verification requirements."""
    VERIFIED = "verified"        # confirmed with 2+ methods (required for CRITICAL/HIGH)
    PROBABLE = "probable"        # strong indicators, single method
    UNVERIFIED = "unverified"    # initial observation, needs confirmation


class RemediationPriority(str, Enum):
    """Remediation urgency (PTES/CREST)."""
    IMMEDIATE = "immediate"      # 0-7 days
    SHORT_TERM = "short-term"    # ~30 days
    LONG_TERM = "long-term"      # 90+ days


@dataclass
class Evidence:
    """An artifact backing a finding (points to a file in the engagement workspace)."""
    type: str                    # scan-output | http-request | terminal-log | screenshot | artifact
    path: str                    # relative path within the workspace
    description: str = ""
    sha256: str = ""             # integrity / chain-of-custody
    collected_at: str = ""       # ISO 8601


@dataclass
class ReportFinding:
    """One vulnerability in the final report — the schema the Reporter agent fills."""
    # --- Identity ---
    id: str                      # FIND-001, FIND-002, ...
    title: str                   # "[Type] in [Target] allows [Impact]"
    severity: Severity
    affected_target: str         # URL / host of the affected web app
    description: str             # technical description

    # --- Scoring ---
    cvss_score: float | None = None
    cvss_vector: str = ""        # e.g. CVSS:4.0/AV:N/AC:L/...
    cvss_version: str = "4.0"
    cwe: list[str] = field(default_factory=list)      # e.g. ["CWE-89"] for SQLi
    mitre: list[str] = field(default_factory=list)    # ATT&CK technique IDs (from Step 7), e.g. ["T1190"]

    # --- Where / What ---
    affected_component: str = ""                      # endpoint / parameter
    steps_to_reproduce: list[str] = field(default_factory=list)
    negative_control: str = ""   # the control that rules out a false positive (see methodology)
    impact: str = ""

    # --- Evidence & verification ---
    evidence: list[Evidence] = field(default_factory=list)
    confidence: Confidence = Confidence.UNVERIFIED
    verified_methods: list[str] = field(default_factory=list)  # e.g. ["sqlmap", "manual curl"]

    # --- Remediation ---
    remediation: str = ""
    remediation_priority: RemediationPriority | None = None

    # --- Provenance ---
    agent: str = ""              # which agent found it: recon / exploit / ...


# CVSS score -> severity band (identical bands to Decepticon).
def severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFORMATIONAL


def validate_finding(f: ReportFinding) -> list[str]:
    """Check a finding against the methodology. Returns a list of problems (empty = valid)."""
    problems: list[str] = []

    # Severity must match the CVSS band when a score is provided.
    if f.cvss_score is not None and severity_from_cvss(f.cvss_score) != f.severity:
        want = severity_from_cvss(f.cvss_score).value
        problems.append(f"severity '{f.severity.value}' does not match CVSS {f.cvss_score} (expected '{want}')")

    # Critical/High must be VERIFIED (Decepticon rule), and VERIFIED needs 2+ methods.
    if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.confidence != Confidence.VERIFIED:
        problems.append(f"'{f.severity.value}' findings must be VERIFIED; got '{f.confidence.value}'")
    if f.confidence == Confidence.VERIFIED and len(f.verified_methods) < 2:
        problems.append("VERIFIED confidence requires at least 2 verified_methods")

    # A real (non-informational) finding needs reproduction AND a negative control.
    if f.severity != Severity.INFORMATIONAL:
        if not f.steps_to_reproduce:
            problems.append("steps_to_reproduce is required for a real finding")
        if not f.negative_control:
            problems.append("negative_control is required (to rule out a false positive)")

    return problems
