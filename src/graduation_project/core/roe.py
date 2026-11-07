"""Rules of Engagement: the scope allowlist and its enforcement.

This is a *code-level* control, not a prompt instruction. Every target an agent
is about to act on is validated here before dispatch, so an agent cannot be
talked into acting outside the engagement scope even if a finding points at
another host. It complements network isolation (DVWA on its own Docker
network) — it does not replace it.
"""

from __future__ import annotations

from dataclasses import dataclass
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

    def is_in_scope(self, target: str) -> bool:
        host = host_of(target)
        return host is not None and host in self.allowed_hosts

    def enforce(self, target: str) -> None:
        if not self.is_in_scope(target):
            raise RoEViolation(
                f"Target {target!r} is outside the engagement scope "
                f"{sorted(self.allowed_hosts)}"
            )
