"""gobuster wrapper: content/directory discovery on a web target, parsed into
structured facts. Mirrors the other recon tools' shape (ToolUnavailable +
dataclass + run_*/_parse_* helpers).

gobuster `dir` mode does not emit stable JSON, so its quiet-mode text lines
are parsed with an explicit regex:

    /admin                (Status: 301) [Size: 312] [--> /admin/]

The caller is responsible for scope enforcement before this is invoked.
A wordlist is required; the default is Kali's dirb common list. If gobuster
or the wordlist is missing, ToolUnavailable is raised (retryable/skippable by
the agent, exactly like the other tools).
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# Default wordlist shipped by the Kali `dirb` package. Override per call if the
# sandbox image stages a different list (e.g. seclists).
DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt"


class ToolUnavailable(Exception):
    """Raised when the required CLI tool (or its wordlist) is not installed."""


@dataclass
class PathFinding:
    path: str
    status: int
    size: int
    redirect: str = ""

    def as_text(self) -> str:
        bits = [f"{self.path} (Status {self.status}, {self.size} bytes)"]
        if self.redirect:
            bits.append(f"-> {self.redirect}")
        return " ".join(bits)


def run_gobuster_scan(
    target_url: str,
    wordlist: str = DEFAULT_WORDLIST,
    timeout: int = 300,
) -> list[PathFinding]:
    """Run `gobuster dir` against `target_url` and return discovered paths.

    `target_url` must include the scheme (e.g. http://dvwa/). Scope is the
    caller's responsibility.
    """
    if shutil.which("gobuster") is None:
        raise ToolUnavailable("gobuster is not installed on this host")
    if not Path(wordlist).is_file():
        raise ToolUnavailable(f"wordlist not found: {wordlist}")

    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", wordlist,
        "-q",            # quiet: suppress banner/progress, print found paths only
        "-t", "20",      # concurrency
        "--no-error",    # don't print per-request errors to stdout
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"gobuster timed out after {timeout}s") from exc

    # gobuster exits non-zero on some soft conditions but still prints results;
    # only treat "no output at all" as a hard failure.
    if not proc.stdout.strip():
        detail = proc.stderr.strip() or f"gobuster exited {proc.returncode} with no output"
        raise RuntimeError(detail)

    return _parse_gobuster_text(proc.stdout)


# Matches:  /admin  (Status: 301) [Size: 312] [--> /admin/]
# The redirect group is optional.
_LINE_RE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)\s*"
    r"\[Size:\s*(?P<size>\d+)\]"
    r"(?:\s*\[-->\s*(?P<redirect>[^\]]+)\])?"
)


def _parse_gobuster_text(text: str) -> list[PathFinding]:
    findings: list[PathFinding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        match = _LINE_RE.match(line)
        if not match:
            continue
        findings.append(
            PathFinding(
                path=match.group("path"),
                status=int(match.group("status")),
                size=int(match.group("size")),
                redirect=(match.group("redirect") or "").strip(),
            )
        )
    return findings
