"""LLM decision layer for Recon: Gemini looks at what nmap/nikto/headers
already found and suggests a short list of *additional, still passive*
paths worth probing (e.g. /robots.txt, /.git/config, /phpinfo.php).

This is the "AI" half of the hybrid design: the tools stay deterministic
code (reliable, reproducible); the LLM only decides *what to check next*,
never *how to exploit anything*. The model is asked explicitly for
information-gathering suggestions only, and whatever it returns is still
validated and scope-checked by the caller before anything is fetched —
never trusted blindly.

Degrades gracefully: if the SDK isn't installed, no API key is configured,
or the call fails for any reason, callers should treat that as "no
suggestions" and continue with the deterministic findings alone.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

MAX_SUGGESTIONS = 5

_PROMPT_TEMPLATE = """You are assisting a Recon agent in an authorized, scoped \
penetration-testing engagement against a single pre-approved target.

Your ONLY job: given the reconnaissance evidence below, suggest up to {max_n} \
additional PASSIVE, non-destructive paths worth fetching with a plain HTTP GET \
to gather more information (e.g. common config/info-leak files, backup files, \
admin panels, robots.txt). Do NOT suggest anything that modifies data, submits \
forms, brute-forces credentials, or attempts to exploit a vulnerability — this \
step is reconnaissance only.

Respond with ONLY a JSON array of relative URL paths, each starting with "/". \
Example: ["/robots.txt", "/admin", "/.git/config"]
If nothing useful comes to mind, respond with [].

Reconnaissance evidence so far:
{evidence}
"""


class LLMUnavailable(Exception):
    """Raised when the LLM planning step cannot run (no key, no SDK, etc.)."""


@dataclass
class PlannedProbe:
    path: str


def suggest_probes(evidence_summary: str, api_key: str) -> list[PlannedProbe]:
    """Ask Gemini for a short list of additional passive paths to check.

    Raises LLMUnavailable on any failure (missing key, missing SDK, API
    error, unparseable response) so the caller can skip this step cleanly
    rather than letting an LLM hiccup fail the whole Recon objective.
    """
    if not api_key:
        raise LLMUnavailable("no GEMINI_API_KEY configured")

    try:
        import google.generativeai as genai
    except ImportError as exc:
        raise LLMUnavailable("google-generativeai package is not installed") from exc

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.0-flash")
        prompt = _PROMPT_TEMPLATE.format(max_n=MAX_SUGGESTIONS, evidence=evidence_summary)
        response = model.generate_content(prompt)
        text = (response.text or "").strip()
    except Exception as exc:  # network error, auth error, SDK error, etc.
        raise LLMUnavailable(f"Gemini call failed: {exc}") from exc

    return _parse_suggestions(text)


def _parse_suggestions(text: str) -> list[PlannedProbe]:
    # Models sometimes wrap JSON in a ```json ... ``` fence despite instructions.
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        raise LLMUnavailable(f"could not find a JSON array in LLM response: {text[:200]!r}")

    try:
        paths = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise LLMUnavailable(f"LLM response was not valid JSON: {exc}") from exc

    if not isinstance(paths, list):
        raise LLMUnavailable("LLM response JSON was not a list")

    probes: list[PlannedProbe] = []
    for p in paths[:MAX_SUGGESTIONS]:
        if not isinstance(p, str):
            continue
        # Defense in depth: only accept same-origin relative paths. Reject
        # absolute URLs, scheme changes, or traversal — the caller will also
        # re-resolve and RoE-check the final URL, but don't even offer a
        # path that looks like it's trying to leave the target.
        if not p.startswith("/") or "://" in p or ".." in p:
            continue
        probes.append(PlannedProbe(path=p))
    return probes
