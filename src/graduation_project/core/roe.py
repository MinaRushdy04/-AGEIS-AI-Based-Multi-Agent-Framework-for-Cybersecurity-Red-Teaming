"""Rules of Engagement: the scope allowlist and its enforcement.

This is a *code-level* control, not a prompt instruction. Every target an agent
is about to act on is validated here before dispatch, so an agent cannot be
talked into acting outside the engagement scope even if a finding points at
another host. It complements network isolation (DVWA on its own Docker
network) — it does not replace it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


class RoEViolation(Exception):
    """Raised when a target falls outside the engagement scope."""


def host_of(target: str | None) -> str | None:
    """Best-effort hostname extraction from a URL or host[:port] string."""
    if not target:
        return None
    # urlparse needs a scheme to populate .hostname; synthesize one if absent.
    parsed = urlparse(target if "://" in target else f"//{target}")
    host = (parsed.hostname or "").lower()
    return host or None


@dataclass(frozen=True)
class RulesOfEngagement:
    allowed_hosts: frozenset[str]

    @classmethod
    def for_target(cls, target: str) -> "RulesOfEngagement":
        host = host_of(target)
        if host is None:
            raise ValueError(f"Cannot derive a host from target {target!r}")
        return cls(allowed_hosts=frozenset({host}))

    @classmethod
    def from_roe_file(cls, path: str | Path = "plan/roe.json") -> "RulesOfEngagement":
        """Build the scope allowlist from the ``machine_enforcement`` block of a
        Rules-of-Engagement JSON file (``plan/roe.json``).

        This is the Decepticon pattern: the orchestrator guard rail reads the
        machine RoE rather than a single hardcoded target, so the engagement
        scope comes from one reviewed source of truth. Only the in-scope hosts
        become the allowlist; anything else (including the file's out_of_scope
        list) is rejected by ``enforce`` because it is not in the allowlist.
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        machine = data.get("machine_enforcement", {})
        hosts = {
            (entry.get("target") or "").lower()
            for entry in machine.get("in_scope", [])
            if entry.get("target")
        }
        if not hosts:
            raise ValueError(
                f"no in-scope hosts in machine_enforcement of {path!r}"
            )
        return cls(allowed_hosts=frozenset(hosts))

    def is_in_scope(self, target: str) -> bool:
        host = host_of(target)
        return host is not None and host in self.allowed_hosts

    def enforce(self, target: str) -> None:
        if not self.is_in_scope(target):
            raise RoEViolation(
                f"Target {target!r} is outside the engagement scope "
                f"{sorted(self.allowed_hosts)}"
            )
