# Rules of Engagement (RoE)

**Project:** AEGIS — AI-Based Multi-Agent Framework for Cybersecurity Red Teaming
**Scope of this document:** Web-application red teaming inside a closed training lab
**Version:** 1.0  **Last updated:** 2026-11-23

---

## 1. Purpose

This document defines **what the AI agent is allowed to attack, what it is forbidden from
touching, and under what authorization.** It exists for two reasons:

1. **Safety & legitimacy** — a red-team agent must only act against explicitly authorized
   targets. The RoE is the single source of truth for that boundary.
2. **Enforcement** — these rules are also written in machine-readable form (`roe.json`,
   `machine_enforcement` block) so the agent itself can respect them at runtime, exactly as
   in the Decepticon reference project.

---

## 2. Environment

All testing happens inside a **closed, isolated Docker lab** that we own and operate:

- The attacker (Kali sandbox) and the targets live on an **internal, air-gapped network**
  (`sandbox-net`, `internal: true`) with **no internet access**.
- No production systems, no third parties, and no real user data are involved at any point.
- Therefore all testing is **self-authorized** within this environment.

---

## 3. Authorization Statement

> This is a closed academic training lab, owned and operated by the AEGIS project team.
> No external, third-party, or production systems are in scope. All red-team activity is
> confined to the isolated lab network and is authorized by the project team for the purpose
> of training and evaluating the AI agent.

---

## 4. In-Scope Targets (authorized)

| Target | Type | Notes |
|--------|------|-------|
| `dvwa` | Web application | DVWA — reached inside the lab as `http://dvwa/`. The authorized web target. |

> The agent may run reconnaissance, scanning, and web-vulnerability exploitation against the
> targets in this table **only**.

---

## 5. Out-of-Scope (forbidden)

| Target | Why it is forbidden |
|--------|---------------------|
| `sandbox` (Kali) | The attacker machine itself — never a target. |
| `bridge`, `infra` | Lab infrastructure / management-plane services. |
| `metasploitable2` | Reserve target — **not** authorized until explicitly moved in-scope. |
| `management-net` | Management plane — strictly off-limits. |
| The internet | The lab is air-gapped and must stay air-gapped. |

---

## 6. Prohibited Actions

- Attacking any host other than the in-scope web target(s).
- Any traffic that leaves `sandbox-net`.
- Denial of Service (DoS / DDoS) against any target.
- Destructive commands (deleting/modifying files outside the agent workspace).
- Attempting to escape the sandbox container or reach the host / management plane.

## 7. Permitted Actions

- Web-application testing against in-scope targets only: recon, scanning, and exploitation of
  OWASP-class web vulnerabilities.
- Using the installed tools (nmap, nikto, gobuster, sqlmap, curl) against in-scope web targets.

---

## 8. How the RoE is enforced

The same rules exist in two forms:

- **This document** — human-readable, for review and sign-off.
- **`roe.json`** — machine-readable. Its `machine_enforcement` block is what the agent reads
  at runtime (same format and location as Decepticon: `<workspace>/plan/roe.json`). Because
  `in_scope` is a non-empty allowlist, every target that is not explicitly in scope is denied
  by default.

---

## 9. Adding a new target later (e.g. OWASP Juice Shop, or our own demo web app)

When a new **web** target is introduced, authorize it in **two places** in `roe.json`:

1. In the human **`in_scope`** list (with a `notes` description), and
2. In the **`machine_enforcement.in_scope`** list (so the agent enforces it), e.g.:

```json
{ "target": "juice-shop", "type": "host" }
```

Then update this document's In-Scope table and bump the `version` / `last_updated`.
No target is live for the agent until it appears in **both** places.
