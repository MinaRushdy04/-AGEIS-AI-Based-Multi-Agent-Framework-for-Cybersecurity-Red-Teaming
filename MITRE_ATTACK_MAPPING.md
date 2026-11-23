# MITRE ATT&CK Mapping (Step 7)

**Project:** AEGIS — AI-Based Multi-Agent Framework for Cybersecurity Red Teaming
**Purpose:** Map each tool / agent action to its MITRE ATT&CK technique, for use in
reporting and evaluation.
**Catalog:** MITRE ATT&CK Enterprise **v19.2** (same catalog the Decepticon reference
project uses). Every technique below was validated to exist in that catalog and to belong
to the stated tactic (see §4).

---

## 0. Scope — WEB APPLICATION

Decepticon is a broad framework: it covers Active Directory, cloud, network, mobile, smart
contracts and more. **This project deliberately implements only the WEB APPLICATION layer of
Decepticon.** Accordingly, the kill chain here is: web reconnaissance → web exploitation →
the post-exploitation that follows once a web application is compromised (a shell on the
host). Domains outside web application (AD, cloud, wireless, etc.) are not implemented.

## 1. What this is

MITRE ATT&CK is a standard, world-wide vocabulary for classifying attacker behaviour. Each
action has:

- a **Tactic** — the attacker's goal (e.g. *Reconnaissance*), with an ID like `TA0043`;
- a **Technique** — how it is done, with an ID like `T1595.003`.

When the agent performs an action, the final report cites the matching technique. This gives
the report a professional, standardised language and lets the work be evaluated against a
recognised framework.

## 2. Alignment with Decepticon

These mappings are not invented — they follow how Decepticon annotates the same actions:

- Decepticon's `active-recon` skill is tagged `T1595, T1595.001, T1595.002, T1595.003`
  → our recon tools (nmap, nikto, gobuster, header check) map into that Active Scanning family.
- Decepticon's web-exploitation skills are tagged `T1190` → sqlmap / web exploitation.
- Brute force → `T1110`; host enumeration (post-exploit) → `T1082 / T1083`.

## 3. The mapping

Each tool writes a `source` tag into every `Finding`; the reporter looks that tag up here.

| Tool | Agent phase | Tactic | Technique ID | Technique name |
|------|-------------|--------|--------------|----------------|
| **nmap** | Web recon *(live)* | Reconnaissance (TA0043) | `T1595.001` | Active Scanning: Scanning IP Blocks |
| **nikto** | Web recon *(live)* | Reconnaissance (TA0043) | `T1595.002` | Active Scanning: Vulnerability Scanning |
| **header_check** | Web recon *(live)* | Reconnaissance (TA0043) | `T1595.002` | Active Scanning: Vulnerability Scanning |
| **gobuster** | Web recon *(live)* | Reconnaissance (TA0043) | `T1595.003` | Active Scanning: Wordlist Scanning |
| **sqlmap** | Web exploit *(planned)* | Initial Access (TA0001) | `T1190` | Exploit Public-Facing Application |
| **metasploit** | Exploit *(planned)* | Initial Access (TA0001) | `T1190` | Exploit Public-Facing Application |
| **hydra** | Web-auth attack *(planned)* | Credential Access (TA0006) | `T1110.001` | Brute Force: Password Guessing |
| **linpeas** | Post-exploit *(planned)* | Discovery (TA0007) | `T1082` | System Information Discovery |

- **live** = produced by the current ReconAgent today.
- **planned** = the tool is installed and mapped, ready for the Exploit / Post-Exploit agents.
- `metasploit` and `linpeas` sit in the **post-exploitation** continuation of the web kill
  chain (used after a web app is compromised and a host shell is obtained).
- `linpeas` also relates to `T1083 File and Directory Discovery`; `T1082` is its primary technique.

## 4. Verification

The mapping lives in `core/attack_map.py` as a simple lookup (`source → technique`). It was
checked programmatically against Decepticon's ATT&CK catalog file: **all entries passed** —
every `technique_id` exists in catalog v19.2 and belongs to the tactic shown above. The check
can be re-run any time the mapping changes.

## 5. How the reporter uses it

```python
from graduation_project.core.attack_map import technique_for

t = technique_for(finding.data["source"])   # e.g. "gobuster"
if t:
    report_line = f"{finding.title}  [{t.technique_id} {t.technique_name}]"
```

Adding a new tool later = add one line to `ATTACK_MAP` and re-run the verification.
