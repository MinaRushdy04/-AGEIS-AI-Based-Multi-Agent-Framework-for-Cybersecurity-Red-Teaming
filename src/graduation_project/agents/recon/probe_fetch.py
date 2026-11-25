"""Safe GET-only fetch for a single path, used to follow up on LLM-suggested
recon probes. Deliberately minimal: no form submission, no custom headers
that could carry an attack payload, no rediroutes outside the resolved host.
"""

from __future__ import annotations

import shutil
import subprocess


class ToolUnavailable(Exception):
    pass


def fetch_path(url: str, timeout: int = 15) -> tuple[int, str]:
    """GET `url` and return (status_code, first ~500 chars of the body).

    Uses curl rather than `requests` so this module has the same
    "shell out to a standard CLI tool" shape as the rest of Recon, with no
    extra Python dependency.
    """
    if shutil.which("curl") is None:
        raise ToolUnavailable("curl is not installed on this host")

    cmd = [
        "curl", "-s", "-o", "-", "-w", "\n__STATUS__:%{http_code}",
        "--max-time", str(timeout), url,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 5, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"curl timed out after {timeout}s") from exc

    output = proc.stdout
    if "__STATUS__:" not in output:
        detail = proc.stderr.strip() or f"curl exited {proc.returncode} with no output"
        raise RuntimeError(detail)

    body, _, status_part = output.rpartition("__STATUS__:")
    status_code = int(status_part.strip() or "0")
    return status_code, body[:500]
