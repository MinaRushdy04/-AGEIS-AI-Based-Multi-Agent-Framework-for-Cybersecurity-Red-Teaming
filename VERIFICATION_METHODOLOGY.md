# Verification & Reporting Methodology (Step 9)

**Project:** AEGIS — AI-Based Multi-Agent Framework for Cybersecurity Red Teaming
**Scope:** Web application findings.
**Basis:** A lightweight, web-focused version of the Decepticon reference project's
finding-epistemics discipline (PTES / CREST reporting standards, CVSS-aligned severity,
ATT&CK mapping). Implemented in `core/report_schema.py` and verified by a test (§3).

---

## Part A — Confirming a finding is REAL (verification)

Before a finding is reported, it must be shown to be real, not a false positive. Two things
are required for every real (non-informational) finding:

### 1. Reproduction steps
An ordered, repeatable list of steps that trigger the vulnerability. If the steps don't
reproduce it, it isn't reported.

### 2. A negative control
A control observation that rules out coincidence. We confirm the *vulnerable* behaviour **and**
show that a benign/normal input does **not** produce it — so the difference is the
vulnerability, not something incidental.

> Example (SQL injection on DVWA):
> - **Positive:** `id=1' OR '1'='1'` returns *all* users.
> - **Negative control:** `id=1` returns *exactly one* user.
> The gap between the two is the proof the injection is real.

### 3. Confidence level (gates severity)
Each finding carries a confidence that drives how much verification is required:

| Confidence | Meaning | Requirement |
|------------|---------|-------------|
| `verified` | Confirmed with **2+ methods** | **Required for Critical / High** |
| `probable` | Strong indicators, single method | Allowed for Medium / Low |
| `unverified` | Initial observation | Must be confirmed before reporting high severity |

So a **Critical or High** finding may only be filed when it is `verified` with at least two
independent methods (e.g. `sqlmap` **and** a manual `curl`).

---

## Part B — The report schema (what the Reporter agent fills)

Every finding in the final report follows one schema (`core/report_schema.py` →
`ReportFinding`). Key fields:

| Field | Purpose |
|-------|---------|
| `id`, `title` | `FIND-001`; title in bug-bounty form `[Type] in [Target] allows [Impact]` |
| `severity` | CVSS-aligned band: critical / high / medium / low / informational |
| `cvss_score`, `cvss_vector`, `cvss_version` | CVSS 4.0 score + vector (severity must match the band) |
| `cwe` | CWE IDs, e.g. `CWE-89` (SQLi) |
| `mitre` | **ATT&CK technique IDs — the link to Step 7**, e.g. `T1190` |
| `affected_target`, `affected_component` | the URL + endpoint/parameter |
| `description`, `impact` | what it is and what it lets an attacker do |
| `steps_to_reproduce`, `negative_control` | the verification from Part A |
| `evidence` | artifacts (scan output, HTTP request/response, logs) with SHA-256 |
| `confidence`, `verified_methods` | how sure, and by which methods |
| `remediation`, `remediation_priority` | the fix + urgency (immediate / short-term / long-term) |

### Severity bands (CVSS-aligned)

| Severity | CVSS |
|----------|------|
| Critical | 9.0 – 10.0 |
| High | 7.0 – 8.9 |
| Medium | 4.0 – 6.9 |
| Low | 0.1 – 3.9 |
| Informational | 0.0 |

---

## 3. Verification (of this methodology)

`core/report_schema.py` ships a `validate_finding()` check that enforces the rules above.
It was tested and **all checks pass**:

- CVSS score → correct severity band.
- A well-formed DVWA SQLi finding validates clean.
- A **Critical finding that is not `verified`** is rejected.
- A **severity that doesn't match its CVSS score** is rejected.
- A finding **missing its negative control** is rejected.

This gives the Reporter agent a schema it must satisfy, so no finding reaches the report
without reproduction, a negative control, matching severity, and (for high severity) 2-method
verification.
