"""nikto wrapper: web-specific scan for exposed paths, outdated software,
and other findings nikto reports. Uses nikto's own JSON output format so
parsing doesn't depend on screen-scraping plain text, with a plain-text
fallback for older nikto builds that don't support `-Format json`.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class ToolUnavailable(Exception):
    """Raised when the required CLI tool is not installed."""


@dataclass
class NiktoFinding:
    item_id: str
    url: str
    message: str


def run_nikto_scan(target_url: str, timeout: int = 300) -> list[NiktoFinding]:
    if shutil.which("nikto") is None:
        raise ToolUnavailable("nikto is not installed on this host")

    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = Path(tmp_dir) / "nikto_out.json"
        cmd = [
            "nikto",
            "-h", target_url,
            "-Format", "json",
            "-o", str(out_path),
            "-ask", "no",
        ]
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(f"nikto timed out after {timeout}s") from exc

        if out_path.exists() and out_path.stat().st_size > 0:
            return _parse_nikto_json(out_path.read_text(encoding="utf-8", errors="replace"))

        # Fallback: nikto refused/doesn't support -Format json, or crashed
        # before writing output; salvage what we can from stdout.
        text = proc.stdout or ""
        if not text.strip():
            detail = proc.stderr.strip() or f"nikto exited {proc.returncode} with no output"
            raise RuntimeError(detail)
        return _parse_nikto_text(text)


def _parse_nikto_json(raw: str) -> list[NiktoFinding]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return _parse_nikto_text(raw)

    # Nikto's JSON shape has varied across versions: sometimes a single
    # object with a "vulnerabilities" list, sometimes a bare list of scans.
    entries: list[dict] = []
    if isinstance(data, dict):
        entries.extend(data.get("vulnerabilities", []))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                entries.extend(item.get("vulnerabilities", [item]))

    findings = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        findings.append(
            NiktoFinding(
                item_id=str(entry.get("id", "")),
                url=str(entry.get("url", "")),
                message=str(entry.get("msg", entry.get("message", ""))).strip(),
            )
        )
    return findings


_TEXT_LINE_RE = re.compile(r"^\+\s*(?P<url>\S+)?:?\s*(?P<msg>.+)$")


def _parse_nikto_text(text: str) -> list[NiktoFinding]:
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("+") or line.startswith("+ Target") or line.startswith("+ Server"):
            if line.startswith("+ Server"):
                findings.append(NiktoFinding(item_id="server-banner", url="", message=line[2:].strip()))
            continue
        match = _TEXT_LINE_RE.match(line)
        if match:
            findings.append(
                NiktoFinding(item_id="", url=match.group("url") or "", message=match.group("msg").strip())
            )
    return findings
