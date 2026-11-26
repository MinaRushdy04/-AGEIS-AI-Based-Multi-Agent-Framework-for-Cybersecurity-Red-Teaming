"""metasploit wrapper: runs a module's `check` against a target and parses the
resulting CheckCode into a structured fact. Mirrors the other tools' shape
(ToolUnavailable + dataclass + run_*/_parse_* helpers).

DETECTION ONLY — NON-DESTRUCTIVE. It ONLY issues the `check` command, which asks
a module whether the target *appears* exploitable WITHOUT launching any payload
or exploit. It never runs `exploit`/`run`, so nothing on the target is changed.

Metasploit shines against services with a known CVE/exploit module (not DVWA's
intentional web bugs, which sqlmap/hydra already cover). This wrapper is kept
generic so the agent can check any in-scope host that has a matching module.

`msfconsole` prints the CheckCode on one line, e.g.:
    [+] 10.0.0.5:445 - The target is vulnerable.
    [*] 10.0.0.5:80  - The target appears to be vulnerable.
    [-] 10.0.0.5:80  - The target is not exploitable.

The caller enforces scope and passes an authorized target only. If msfconsole
is not installed, ToolUnavailable is raised (retryable/skippable by the agent,
exactly like the other tools).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

# CheckCode text -> normalized state (ordered: first match wins).
_STATE_PATTERNS = [
    ("vulnerable", re.compile(r"\bThe target is vulnerable\b", re.I)),
    ("appears",    re.compile(r"\bappears to be vulnerable\b", re.I)),
    ("detected",   re.compile(r"\b(?:is running the service|could not be validated|detected)\b", re.I)),
    ("safe",       re.compile(r"\b(?:is not exploitable|does not appear to be vulnerable)\b", re.I)),
    ("unsupported", re.compile(r"\bdoes not support check\b", re.I)),
    ("unknown",    re.compile(r"\bCannot reliably check exploitability\b", re.I)),
]
_VULN_STATES = {"vulnerable", "appears"}   # states that indicate a real finding


class ToolUnavailable(Exception):
    """Raised when the required CLI tool (msfconsole) is not installed."""


@dataclass
class VulnCheckFinding:
    module: str
    state: str          # vulnerable | appears | detected | safe | unsupported | unknown
    target: str
    detail: str = ""

    @property
    def is_vulnerable(self) -> bool:
        return self.state in _VULN_STATES

    def as_text(self) -> str:
        return f"{self.module} check on {self.target}: {self.state}"


def run_metasploit_check(
    target_host: str,
    module: str,
    rport: int | None = None,
    options: dict[str, str] | None = None,
    timeout: int = 300,
) -> list[VulnCheckFinding]:
    """Run `check` for one metasploit exploit `module` against `target_host`.

    `module` is a full module path (e.g. "exploit/unix/webapp/...").
    `rport`/`options` set extra datastore values. NON-DESTRUCTIVE: only `check`
    runs. Scope is the caller's responsibility.
    """
    if shutil.which("msfconsole") is None:
        raise ToolUnavailable("msfconsole (metasploit-framework) is not installed on this host")

    cmds = [f"use {module}", f"set RHOSTS {target_host}"]
    if rport:
        cmds.append(f"set RPORT {rport}")
    for key, val in (options or {}).items():
        cmds.append(f"set {key} {val}")
    cmds += ["check", "exit -y"]
    script = "; ".join(cmds)

    try:
        proc = subprocess.run(
            ["msfconsole", "-q", "-n", "-x", script],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"msfconsole timed out after {timeout}s") from exc

    return _parse_msf_check(proc.stdout, module=module, target=target_host)


def _parse_msf_check(text: str, module: str, target: str) -> list[VulnCheckFinding]:
    """Read msfconsole output and return one VulnCheckFinding with the CheckCode
    state. Technique-agnostic: it only classifies the check result line."""
    state, detail = "unknown", ""
    for name, pat in _STATE_PATTERNS:
        m = pat.search(text)
        if m:
            state = name
            # capture the whole status line as evidence
            line = next((ln.strip() for ln in text.splitlines() if pat.search(ln)), "")
            detail = line
            break
    return [VulnCheckFinding(module=module, state=state, target=target, detail=detail)]
