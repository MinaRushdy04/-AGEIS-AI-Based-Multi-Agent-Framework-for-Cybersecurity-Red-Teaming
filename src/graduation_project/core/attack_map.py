"""MITRE ATT&CK mapping (Step 7) — web-application focused.

PROJECT SCOPE: Decepticon covers many domains (Active Directory, cloud, network,
mobile, smart contracts...). This project deliberately focuses on the **web
application** layer: the kill chain starts with web reconnaissance and web
exploitation, and continues into the post-exploitation that follows once a web
app is compromised (shell on the host).

Maps each tool (by the `source` tag it writes into `Finding.data`) to its MITRE
ATT&CK tactic + technique. IDs and names follow the ATT&CK Enterprise catalog
and mirror how Decepticon classifies the same actions (its `active-recon` skill
is annotated T1595/.001/.002/.003; web-exploitation skills T1190; brute force
T1110; host enumeration T1082/T1083).

Used by the reporter/evaluation: given a Finding, look up its `source` to get
the ATT&CK technique to cite. Kept as a pure lookup so it touches neither the
shared `Finding` contract nor the agents.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str      # e.g. "T1595.003"
    technique_name: str    # e.g. "Active Scanning: Wordlist Scanning"
    tactic_id: str         # e.g. "TA0043"
    tactic_name: str       # e.g. "Reconnaissance"


# source tag (Finding.data["source"]) -> ATT&CK technique.
#
# RECON tools are live in the current ReconAgent. The EXPLOIT / POST-EXPLOIT
# entries are included so the mapping is ready when those agents come online;
# they are not produced by the recon-only agent yet.
ATTACK_MAP: dict[str, AttackTechnique] = {
    # --- Web reconnaissance (active today) ---
    "nmap":         AttackTechnique("T1595.001", "Active Scanning: Scanning IP Blocks",    "TA0043", "Reconnaissance"),
    "nikto":        AttackTechnique("T1595.002", "Active Scanning: Vulnerability Scanning", "TA0043", "Reconnaissance"),
    "header_check": AttackTechnique("T1595.002", "Active Scanning: Vulnerability Scanning", "TA0043", "Reconnaissance"),
    "gobuster":     AttackTechnique("T1595.003", "Active Scanning: Wordlist Scanning",      "TA0043", "Reconnaissance"),
    # --- Web exploitation / web-auth attacks (future Exploit agent) ---
    "sqlmap":       AttackTechnique("T1190",     "Exploit Public-Facing Application",       "TA0001", "Initial Access"),
    "metasploit":   AttackTechnique("T1190",     "Exploit Public-Facing Application",       "TA0001", "Initial Access"),
    "hydra":        AttackTechnique("T1110.001", "Brute Force: Password Guessing",          "TA0006", "Credential Access"),
    # --- Post-exploitation discovery (after a web app is compromised) ---
    "linpeas":      AttackTechnique("T1082",     "System Information Discovery",            "TA0007", "Discovery"),
}


def technique_for(source: str) -> AttackTechnique | None:
    """Return the ATT&CK technique for a tool's `source` tag, or None if unmapped."""
    return ATTACK_MAP.get(source)
