# AEGIS — AI-Based Multi-Agent Framework for Cybersecurity Red Teaming

**CEAI · SUE · Class of '27 Graduation Project** — prepared by a 3‑person squad.
**Supervisors:** Dr. Hesham Hamed Amin · EmadelDin Abbas Mazied
**Reference project:** [Decepticon](https://github.com/PurpleAILAB/Decepticon)

AEGIS is an AI‑driven, multi‑agent framework that performs **web‑application
red‑teaming** inside a closed, isolated Docker lab. A deterministic orchestrator
drives a pipeline of specialized agents (recon → exploit → verify → report)
against an authorized vulnerable target (DVWA), under machine‑enforced Rules of
Engagement.

> **Scope:** This project is deliberately limited to the **web‑application
> layer**, tested in a **self‑owned, air‑gapped lab**. No production or
> third‑party systems are involved.

---

## Architecture

| Component | Role |
|-----------|------|
| **Orchestrator** (`core/orchestrator.py`) | Deterministic scheduler (NOT an LLM). Picks the next pending objective by phase, builds a fresh `Task` with the RoE and only the relevant prior findings, **enforces scope in code**, dispatches to the agent, and records the outcome. |
| **Engagement** (`core/engagement.py`) | Phases: `RECON(1) → ENUMERATE(2) → EXPLOIT(3) → VERIFY(4) → REPORT(5)`. |
| **Contracts** (`core/contracts.py`) | `Finding`, `Task`, `AgentResult`, and the `Agent` protocol. Agents never write state; the orchestrator records results. |
| **RoE** (`core/roe.py` + `plan/roe.json`) | Scope allowlist and its enforcement — a code‑level guard rail that complements network isolation. |
| **Store** (`core/store.py`) | Persistent run log / results (SQLite). |
| **Exec API** (`exec_server.py`) | Decepticon‑compatible `/execute` daemon that runs tool commands inside the sandbox, behind a command whitelist **and** RoE enforcement. |

---

## The Lab (Docker)

`docker-compose.yml` brings up the isolated environment:

| Service | Role | Scope |
|---------|------|-------|
| **sandbox** | Kali attacker container (runs the tools + Exec API) | attacker |
| **dvwa** | Damn Vulnerable Web Application — the target | **in scope** |
| **metasploitable2** | Reserve target | **out of scope** (not authorized) |
| **bridge / infra** | Network / management‑plane placeholders | out of scope |

**Networks:** `sandbox-net` (internal, **air‑gapped — no internet**),
`management-net`, and a `web-expose` bridge so DVWA is reachable at
`http://localhost:8080/` for inspection. Isolation is verified by
`sandbox_escape_test.sh` (see below).

---

## Agents & Phases

| # | Agent | Phase | Status |
|---|-------|-------|--------|
| 1 | **Recon** | RECON / ENUMERATE | ✅ built — nmap, nikto, gobuster, header_check |
| 2 | **Exploit** | EXPLOIT | ✅ built — SQLi, LFI, brute force, reflected XSS |
| 3 | **Verifier** | VERIFY | ✅ built — independent reproduction + negative control |
| 4 | **Reporter** | REPORT | ⏳ pending (scaffold) — report content ready (`report_schema.py`, `attack_map.py`) |

---

## Security Tooling

Each tool is wrapped so its raw output is parsed into a structured `Finding`
(see `TOOL_OUTPUT_INTERPRETATION.md`) and mapped to MITRE ATT&CK
(`core/attack_map.py`, see `MITRE_ATTACK_MAPPING.md`).

**Reconnaissance:** `nmap` (T1595.001), `nikto` / `header_check` (T1595.002),
`gobuster` (T1595.003).

**Exploitation** — the Exploit agent uses the tool first and falls back to a
built‑in non‑destructive `curl` probe:

| Tool | Detects | CWE | ATT&CK |
|------|---------|-----|--------|
| **sqlmap** | SQL injection (type + DBMS) | CWE‑89 | T1190 |
| **hydra** | Weak login credentials (web form brute force) | CWE‑307 | T1110.001 |
| **metasploit** | Exploitability `check` (non‑destructive), standalone | — | T1190 |

All exploitation is **detection‑only and non‑destructive** — no `DROP`/`DELETE`/
`UPDATE`, no data dumping, no DoS. Every payload + response is recorded as
evidence.

---

## Rules of Engagement (machine‑enforced)

Scope and boundaries live in **`plan/roe.json`** (human‑readable summary in
`RULES_OF_ENGAGEMENT.md`). The `machine_enforcement` block is read and applied
at two layers:

1. **Orchestrator guard rail** (`RulesOfEngagement.from_roe_file`) — every target
   is checked against the in‑scope allowlist before any agent acts.
2. **Exec API chokepoint** (`exec_server.py`) — every command is checked before
   it runs: out‑of‑scope hosts, destructive command patterns (`rm -rf /`,
   `mkfs`, `dd of=/dev/…`), and forbidden destinations (e.g. cloud‑metadata IPs)
   are rejected with HTTP 403.

Only **DVWA** is in scope; everything else is denied.

---

## Verification Methodology

Findings are confirmed, not assumed (`VERIFICATION_METHODOLOGY.md`):

- **Reproduction** — the Verifier re‑sends the recorded payload using the same
  sender the Exploit agent used (no duplicated attack code).
- **Negative control** — benign input is shown *not* to trigger the vulnerability.
- **Confidence** — `verified` (two independent methods) vs `probable` (single
  method); CVSS‑aligned severity bands (`core/report_schema.py`).

---

## Documentation Index

| Document | Covers |
|----------|--------|
| `RULES_OF_ENGAGEMENT.md` + `plan/roe.json` | Scope, boundaries, machine enforcement |
| `TOOL_OUTPUT_INTERPRETATION.md` | How each tool's output becomes a structured `Finding` |
| `MITRE_ATTACK_MAPPING.md` | Tool → ATT&CK tactic/technique mapping |
| `SANDBOX_ESCAPE_TESTS.md` + `sandbox_escape_test.sh` | Container‑isolation tests (with positive control) |
| `VERIFICATION_METHODOLOGY.md` | Reproduction, negative control, confidence, severity |

---

## Running the Lab

```bash
# 1) Build and start the isolated environment
docker compose up -d --build

# 2) Confirm the sandbox is isolated (expect PASS=7, FAIL=0)
docker compose cp sandbox_escape_test.sh sandbox:/tmp/sandbox_escape_test.sh
docker compose exec sandbox bash /tmp/sandbox_escape_test.sh

# 3) Run the test suite
python -m pytest -q
```

DVWA is reachable for inspection at `http://localhost:8080/`
(default credentials `admin` / `password`, security level `low`).

---

## Tech Stack

- **Language:** Python ≥ 3.12 (package `graduation_project` under `src/`)
- **Orchestration:** deterministic scheduler + agent protocol (Decepticon‑compatible contracts)
- **Exec API:** FastAPI (`/execute`, `/healthz`)
- **Lab:** Docker Compose — Kali sandbox, DVWA target, isolated networks
- **Tooling:** nmap, nikto, gobuster, sqlmap, hydra, metasploit
- **Target:** DVWA (Damn Vulnerable Web Application)

---

## Project Status

**Done:** isolated lab + tooling, Recon / Exploit / Verifier agents, exploit tool
wrappers, machine‑enforced RoE, and the full security‑methodology documentation.

**Pending (team):** the Reporter agent scaffold and the end‑to‑end assembly
(agent service in Compose + full `recon → exploit → verify → report` run).
