"""SQLite persistence for the Turkish educational firewall dashboard."""

from __future__ import annotations

import sqlite3
import math
from contextlib import closing
from pathlib import Path
from typing import Any
import re


def _database_name(database: str | Path) -> str:
    value = str(database)
    if value.startswith("sqlite://"):
        value = value.split("://", 1)[1]
        if value.startswith("//"):
            value = "/" + value[2:]
        elif value.startswith("/"):
            value = value[1:]
    return value


def _is_postgresql(database: str | Path) -> bool:
    value = str(database).lower()
    return value.startswith("postgresql://") or value.startswith("postgres://")


def _sensitive_text(value: object) -> str:
    text = "" if value is None else str(value)
    text = re.sub(
        r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)\b\s*[=:]\s*[^&,\s]+",
        r"\1=[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)([?&](?:password|passwd|pwd|secret|token|api[_-]?key)=[^&#]*)",
        r"[REDACTED]",
        text,
    )
    if len(text) > 4096:
        return text[:4096]
    return text


def connect(database: str | Path) -> sqlite3.Connection:
    if _is_postgresql(database):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as error:
            raise RuntimeError(
                "PostgreSQL support requires the declared psycopg dependency."
            ) from error
        return psycopg.connect(str(database), row_factory=dict_row)

    database_path = _database_name(database)
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA busy_timeout=30000")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def initialize(database: str | Path) -> None:
    if _is_postgresql(database):
        with closing(connect(database)) as connection, connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS inspection_events (
                    id BIGSERIAL PRIMARY KEY,
                    created_at TEXT NOT NULL DEFAULT
                        to_char(CURRENT_TIMESTAMP, 'YYYY-MM-DD HH24:MI:SS'),
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
            connection.execute(
                "CREATE INDEX IF NOT EXISTS ix_inspection_events_created_at "
                "ON inspection_events(created_at DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS ix_inspection_events_decision "
                "ON inspection_events(decision)"
            )
            for statement in (
                "ALTER TABLE inspection_events ADD COLUMN IF NOT EXISTS ai_rf_result TEXT",
                "ALTER TABLE inspection_events ADD COLUMN IF NOT EXISTS ai_rf_confidence REAL",
                "ALTER TABLE inspection_events ADD COLUMN IF NOT EXISTS ai_dl_result TEXT",
                "ALTER TABLE inspection_events ADD COLUMN IF NOT EXISTS ai_dl_confidence REAL",
                "ALTER TABLE inspection_events ADD COLUMN IF NOT EXISTS attack_type TEXT",
            ):
                connection.execute(statement)
        return

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
        connection.execute(
            "CREATE INDEX IF NOT EXISTS ix_inspection_events_created_at "
            "ON inspection_events(created_at DESC)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS ix_inspection_events_decision "
            "ON inspection_events(decision)"
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

    values = (
        _sensitive_text(event["source"]),
        _sensitive_text(event["method"]),
        _sensitive_text(event["path"]),
        event["score"],
        event["decision"],
        " · ".join(_sensitive_text(reason) for reason in event["reasons"]),
        event.get("ai_rf_result"),
        event.get("ai_rf_confidence"),
        event.get("ai_dl_result"),
        event.get("ai_dl_confidence"),
        _sensitive_text(event.get("attack_type")),
    )
    placeholder = "%s" if _is_postgresql(database) else "?"
    placeholders = ", ".join([placeholder] * 11)
    with closing(connect(database)) as connection, connection:
        connection.execute(
            f"""
            INSERT INTO inspection_events (
                source, method, path, score, decision, reasons,
                ai_rf_result, ai_rf_confidence, ai_dl_result, ai_dl_confidence, attack_type
            )
            VALUES ({placeholders})
            """,
            values,
        )


def recent_events(database: str | Path, limit: int = 100) -> list[sqlite3.Row]:
    placeholder = "%s" if _is_postgresql(database) else "?"
    with closing(connect(database)) as connection, connection:
        return connection.execute(
            f"SELECT * FROM inspection_events ORDER BY id DESC LIMIT {placeholder}",
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
