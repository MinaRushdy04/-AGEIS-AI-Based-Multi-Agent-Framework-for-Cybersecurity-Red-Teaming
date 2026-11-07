"""Append-only persistence for findings and the run log.

Deliberately external to any agent's context window: this is the single source
of truth for "what happened", so a run is reproducible and gradeable against a
benchmark. JSONL keeps the MVP dependency-free; a SQLite backend can later sit
behind the same interface.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from graduation_project.core.contracts import Finding
from graduation_project.core.roe import host_of


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._findings: list[Finding] = []

    def log_event(self, kind: str, **fields) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "kind": kind,
            **fields,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

    def add_finding(self, finding: Finding) -> None:
        self._findings.append(finding)
        self.log_event("finding", **asdict(finding))

    def findings_for(
        self, target: str | None = None, objective_id: int | None = None
    ) -> list[Finding]:
        """Selective retrieval — the basis of 'fresh but informed' context.

        Returns only findings matching the given objective and/or target host,
        rather than the whole history, so agents are not re-bloated.
        """
        wanted_host = host_of(target) if target is not None else None
        out: list[Finding] = []
        for f in self._findings:
            if objective_id is not None and f.objective_id != objective_id:
                continue
            if wanted_host is not None and host_of(f.target) != wanted_host:
                continue
            out.append(f)
        return out
