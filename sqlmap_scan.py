"""sqlmap wrapper: confirms SQL injection on a web parameter and reports the
injection type(s) + back-end DBMS, parsed into structured facts. Mirrors the
recon tools' shape (ToolUnavailable + dataclass + run_*/_parse_* helpers).

DETECTION ONLY — NON-DESTRUCTIVE. sqlmap runs with --batch --level=1 --risk=1
and NEVER with --dump / --sql-shell / --os-shell, so it proves the parameter is
injectable (and names the technique + DBMS) without reading or modifying table
data. risk=1 also keeps sqlmap off the heavier OR-based payloads.

sqlmap prints confirmed injections in a stable block:

    ---
    Parameter: id (GET)
        Type: boolean-based blind
        Title: AND boolean-based blind - WHERE or HAVING clause
        Payload: id=1 AND 1234=1234&Submit=Submit

        Type: error-based
        Title: MySQL >= 5.0 AND error-based ...
        Payload: id=1 AND (SELECT 1 FROM ...)
    ---
    back-end DBMS: MySQL >= 5.0

The caller enforces scope and supplies the authenticated DVWA cookie. If sqlmap
is not installed, ToolUnavailable is raised (retryable/skippable by the agent,
exactly like the other tools) so the agent can fall back to its own probe.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field


class ToolUnavailable(Exception):
    """Raised when the required CLI tool (sqlmap) is not installed."""


@dataclass
class InjectionFinding:
    parameter: str
    method: str                                       # "GET" / "POST"
    types: list[str] = field(default_factory=list)    # e.g. ["boolean-based blind", "error-based"]
    payload: str = ""                                 # one representative payload (evidence)
    dbms: str = ""

    def as_text(self) -> str:
        bits = [f"{self.parameter} ({self.method}) is injectable"]
        if self.types:
            bits.append("via " + ", ".join(self.types))
        if self.dbms:
            bits.append(f"[DBMS: {self.dbms}]")
        return " ".join(bits)


def run_sqlmap_scan(
    target_url: str,
    cookie: str = "",
    parameter: str | None = None,
    timeout: int = 300,
) -> list[InjectionFinding]:
    """Run sqlmap (detection only) against `target_url` and return confirmed
    injection points.

    `target_url` must include the scheme and the parameter with a sample value
    (e.g. http://dvwa/vulnerabilities/sqli/?id=1&Submit=Submit). `cookie` is the
    authenticated DVWA cookie ("PHPSESSID=...; security=low"). `parameter`
    optionally focuses one parameter. Scope is the caller's responsibility.
    """
    if shutil.which("sqlmap") is None:
        raise ToolUnavailable("sqlmap is not installed on this host")

    cmd = [
        "sqlmap",
        "-u", target_url,
        "--batch",             # never prompt; use safe defaults (no data dump)
        "--level=1",           # minimal test breadth
        "--risk=1",            # lowest risk: no heavy / OR-based payloads
        "--disable-coloring",  # clean text for parsing
    ]
    if cookie:
        cmd += ["--cookie", cookie]
    if parameter:
        cmd += ["-p", parameter]   # focus a single parameter

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"sqlmap timed out after {timeout}s") from exc

    return _parse_sqlmap(proc.stdout)


_PARAM_RE = re.compile(r"^Parameter:\s*(?P<name>.+?)\s*\((?P<method>[^)]+)\)\s*$", re.M)
_TYPE_RE = re.compile(r"^\s*Type:\s*(?P<type>.+?)\s*$", re.M)
_PAYLOAD_RE = re.compile(r"^\s*Payload:\s*(?P<payload>.+?)\s*$", re.M)
_DBMS_RE = re.compile(r"^back-end DBMS:\s*(?P<dbms>.+?)\s*$", re.M)
_FENCE_RE = re.compile(r"^-{3,}\s*$", re.M)   # the "---" that closes the injection list


def _parse_sqlmap(text: str) -> list[InjectionFinding]:
    """Parse sqlmap stdout into InjectionFinding rows. No technique knowledge —
    it only reads the structured block sqlmap prints."""
    dbms_m = _DBMS_RE.search(text)
    dbms = dbms_m.group("dbms").strip() if dbms_m else ""

    matches = list(_PARAM_RE.finditer(text))
    findings: list[InjectionFinding] = []
    for i, m in enumerate(matches):
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]
        # a parameter block ends at the closing "---" fence (keep later output out)
        fence = _FENCE_RE.search(block)
        if fence:
            block = block[:fence.start()]

        types = [t.group("type").strip() for t in _TYPE_RE.finditer(block)]
        payloads = [p.group("payload").strip() for p in _PAYLOAD_RE.finditer(block)]
        findings.append(
            InjectionFinding(
                parameter=m.group("name").strip(),
                method=m.group("method").strip(),
                types=types,
                payload=payloads[0] if payloads else "",
                dbms=dbms,
            )
        )
    return findings
