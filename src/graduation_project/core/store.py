"""SQLite storage for run history and the findings passed to specialists."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from graduation_project.core.contracts import AgentResult, Finding
from graduation_project.core.roe import host_of


class Store:
    """Create a new run, or open a recorded run by its ID."""

    def __init__(self, path: str | Path, *, run_id: str | None = None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = uuid4().hex if run_id is None else run_id
        with closing(self._connect()) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY,
                    run_id TEXT NOT NULL REFERENCES runs(id),
                    ts TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    objective_id INTEGER,
                    target_host TEXT,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS events_by_run ON events(run_id, id);
                CREATE INDEX IF NOT EXISTS findings_by_run_and_host
                    ON events(run_id, target_host) WHERE kind = 'finding';
            """)
            if run_id is None:
                db.execute(
                    "INSERT INTO runs (id, created_at) VALUES (?, ?)",
                    (self.run_id, datetime.now(timezone.utc).isoformat()),
                )
            elif db.execute("SELECT 1 FROM runs WHERE id = ?", (run_id,)).fetchone() is None:
                raise ValueError(f"Unknown run ID: {run_id}")

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path)
        db.execute("PRAGMA foreign_keys = ON")
        return db

    def _event_row(self, kind: str, fields: dict, *, target_host: str | None = None) -> tuple:
        return (
            self.run_id,
            datetime.now(timezone.utc).isoformat(),
            kind,
            fields.get("objective_id"),
            target_host,
            json.dumps(fields, allow_nan=False),
        )

    def _write_events(self, rows: list[tuple]) -> None:
        with closing(self._connect()) as db, db:
            db.executemany(
                """
                INSERT INTO events (run_id, ts, kind, objective_id, target_host, payload)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows,
            )

    def log_event(self, kind: str, **fields) -> None:
        self._write_events([self._event_row(kind, fields)])

    def _finding_row(self, finding: Finding) -> tuple:
        return self._event_row("finding", asdict(finding), target_host=host_of(finding.target))

    def add_finding(self, finding: Finding) -> None:
        self._write_events([self._finding_row(finding)])

    def record_result(self, objective_id: int, attempt: int, result: AgentResult) -> None:
        """Commit the attempt's findings and outcome together."""
        rows = [self._finding_row(finding) for finding in result.findings]
        rows.append(self._event_row("result", {
            "objective_id": objective_id,
            "attempt": attempt,
            "outcome": result.outcome.value,
            "summary": result.summary,
            "flag": bool(result.flag),  # Whether the agent submitted a candidate.
        }))
        self._write_events(rows)

    def findings_for(
        self, target: str | None = None, objective_id: int | None = None
    ) -> list[Finding]:
        """Return findings from this run filtered by objective and/or hostname."""
        if target is not None:
            wanted_host = host_of(target)
            if wanted_host is None:
                return []
        else:
            wanted_host = None
        query = "SELECT payload FROM events WHERE run_id = ? AND kind = 'finding'"
        params: list[str | int] = [self.run_id]
        if wanted_host is not None:
            query += " AND target_host = ?"
            params.append(wanted_host)
        if objective_id is not None:
            query += " AND objective_id = ?"
            params.append(objective_id)
        with closing(self._connect()) as db:
            return [
                Finding(**json.loads(payload))
                for (payload,) in db.execute(query + " ORDER BY id", params)
            ]

    def events(self) -> list[dict]:
        """Read this run's log in the order events were recorded."""
        with closing(self._connect()) as db:
            rows = db.execute(
                "SELECT ts, kind, payload FROM events WHERE run_id = ? ORDER BY id",
                (self.run_id,),
            )
            return [{**json.loads(payload), "ts": ts, "kind": kind} for ts, kind, payload in rows]
