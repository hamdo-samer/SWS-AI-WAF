"""SQLite persistence for the Turkish educational firewall dashboard."""

from __future__ import annotations

import sqlite3
import math
from contextlib import closing
from pathlib import Path
from typing import Any


def connect(database: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(str(database))
    connection.row_factory = sqlite3.Row
    return connection


def initialize(database: str | Path) -> None:
    Path(database).parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(database)) as connection, connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS inspection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime')),
                source TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
                decision TEXT NOT NULL CHECK (decision IN ('İzin verildi', 'Engellendi')),
                reasons TEXT NOT NULL,
                ai_rf_result TEXT,
                ai_rf_confidence REAL CHECK (
                    ai_rf_confidence IS NULL OR ai_rf_confidence BETWEEN 0 AND 1
                ),
                ai_dl_result TEXT,
                ai_dl_confidence REAL CHECK (
                    ai_dl_confidence IS NULL OR ai_dl_confidence BETWEEN 0 AND 1
                ),
                attack_type TEXT
            )
            """
        )
        columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(inspection_events)")
        }
        for column, column_type in (
            ("ai_rf_result", "TEXT"),
            (
                "ai_rf_confidence",
                "REAL CHECK (ai_rf_confidence IS NULL OR ai_rf_confidence BETWEEN 0 AND 1)",
            ),
            ("ai_dl_result", "TEXT"),
            (
                "ai_dl_confidence",
                "REAL CHECK (ai_dl_confidence IS NULL OR ai_dl_confidence BETWEEN 0 AND 1)",
            ),
            ("attack_type", "TEXT"),
        ):
            if column not in columns:
                connection.execute(
                    f"ALTER TABLE inspection_events ADD COLUMN {column} {column_type}"
                )


def add_event(database: str | Path, event: dict[str, Any]) -> None:
    for key in ("ai_rf_confidence", "ai_dl_confidence"):
        confidence = event.get(key)
        if confidence is not None and (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0 <= confidence <= 1
            or not math.isfinite(confidence)
        ):
            raise ValueError(f"{key} must be a finite number between 0 and 1.")

    with closing(connect(database)) as connection, connection:
        connection.execute(
            """
            INSERT INTO inspection_events (
                source, method, path, score, decision, reasons,
                ai_rf_result, ai_rf_confidence, ai_dl_result, ai_dl_confidence, attack_type
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["source"],
                event["method"],
                event["path"],
                event["score"],
                event["decision"],
                " · ".join(event["reasons"]),
                event.get("ai_rf_result"),
                event.get("ai_rf_confidence"),
                event.get("ai_dl_result"),
                event.get("ai_dl_confidence"),
                event.get("attack_type"),
            ),
        )


def recent_events(database: str | Path, limit: int = 100) -> list[sqlite3.Row]:
    with closing(connect(database)) as connection, connection:
        return connection.execute(
            "SELECT * FROM inspection_events ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 1000)),),
        ).fetchall()


def statistics(database: str | Path) -> dict[str, int]:
    with closing(connect(database)) as connection, connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS total,
                   SUM(CASE WHEN decision = 'Engellendi' THEN 1 ELSE 0 END) AS blocked,
                   SUM(CASE WHEN decision = 'İzin verildi' THEN 1 ELSE 0 END) AS allowed
            FROM inspection_events
            """
        ).fetchone()
    return {key: int(row[key] or 0) for key in ("total", "blocked", "allowed")}
