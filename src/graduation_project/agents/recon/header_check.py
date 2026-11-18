"""curl wrapper: fetch response headers and flag missing security headers
and version-revealing banners. Complements nikto's broader web scan with an
explicit, deterministic header check.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field

# Security headers worth flagging when absent. Not exhaustive — enough to
# surface the common hardening gaps during recon.
EXPECTED_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]

# Headers that typically leak software/version info.
BANNER_HEADERS = ["Server", "X-Powered-By"]


class ToolUnavailable(Exception):
    """Raised when the required CLI tool is not installed."""


@dataclass
class HeaderCheckResult:
    headers: dict[str, str] = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)
    banners: dict[str, str] = field(default_factory=dict)


def run_header_check(target_url: str, timeout: int = 20) -> HeaderCheckResult:
    if shutil.which("curl") is None:
        raise ToolUnavailable("curl is not installed on this host")

    cmd = ["curl", "-s", "-D", "-", "-o", "/dev/null", "--max-time", str(timeout), target_url]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 5, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"curl timed out after {timeout}s") from exc

    if not proc.stdout.strip():
        detail = proc.stderr.strip() or f"curl exited {proc.returncode} with no output"
        raise RuntimeError(detail)

    headers = _parse_headers(proc.stdout)
    missing = [h for h in EXPECTED_SECURITY_HEADERS if h.lower() not in {k.lower() for k in headers}]
    banners = {h: headers[h] for h in headers if h in BANNER_HEADERS or h.title() in BANNER_HEADERS}

    return HeaderCheckResult(headers=headers, missing_security_headers=missing, banners=banners)


def _parse_headers(raw: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    # curl -D - may print one header block per redirect hop; keep the last.
    for block in raw.split("\r\n\r\n"):
        block_headers: dict[str, str] = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            block_headers[key.strip()] = value.strip()
        if block_headers:
            headers = block_headers
    return headers
