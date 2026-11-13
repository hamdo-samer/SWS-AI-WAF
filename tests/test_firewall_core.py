import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from firewall_core import inspect_request
from storage import add_event, initialize, recent_events, statistics


class FirewallCoreTests(unittest.TestCase):
    def test_normal_request_is_allowed_and_explained(self):
        result = inspect_request("/urunler", "GET", "", "TestBrowser/1.0")
        self.assertEqual(result.decision, "İzin verildi")
        self.assertEqual(result.score, 0)
        self.assertTrue(result.reasons)

    def test_sql_injection_boolean_payload_is_blocked(self):
        result = inspect_request(
            "/login",
            "GET",
            "user=admin' OR '1'='1",
            "TestBrowser/1.0",
        )

        self.assertEqual(result.decision, "Engellendi")
        self.assertGreaterEqual(result.score, 65)
        self.assertIn("SQL Injection (OR/AND manipülasyonu)", result.reasons)

    def test_xss_script_payload_is_blocked(self):
        result = inspect_request(
            "/search",
            "GET",
            "q=<script>alert('XSS')</script>",
            "TestBrowser/1.0",
        )

        self.assertEqual(result.decision, "Engellendi")
        self.assertIn("Betik etiketi göstergesi", result.reasons)

    def test_percent_encoded_xss_is_blocked_in_path_and_query(self):
        requests = (
            ("/%3Cscript%3E", ""),
            ("/iletisim.html", "name=%3Cscript%3Ealert%28%27Hack%27%29%3C%2Fscript%3E"),
        )

        for path, query in requests:
            with self.subTest(path=path, query=query):
                result = inspect_request(path, "GET", query, "TestBrowser/1.0")

                self.assertEqual(result.decision, "Engellendi")
                self.assertIn("Betik etiketi göstergesi", result.reasons)

    def test_sql_comment_marker_is_detected(self):
        result = inspect_request("/login", "GET", "user=admin--", "TestBrowser/1.0")

        self.assertIn("SQL yorum (comment) göstergesi", result.reasons)

    def test_command_injection_payload_is_blocked(self):
        result = inspect_request(
            "/ping",
            "GET",
            "ip=127.0.0.1; cat /etc/passwd",
            "TestBrowser/1.0",
        )

        self.assertEqual(result.decision, "Engellendi")
        self.assertIn("Komut enjeksiyonu göstergesi", result.reasons)

    def test_long_path_is_capped_and_flagged(self):
        result = inspect_request("/" + "a" * 520, "GET")
        self.assertEqual(result.score, 30)
        self.assertEqual(result.decision, "İzin verildi")
        self.assertIn("İstek yolu beklenenden uzun", result.reasons)

    def test_input_size_is_limited(self):
        with self.assertRaises(ValueError):
            inspect_request("/" + "a" * 4096, "GET")

    def test_events_are_persisted_and_summarized(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "test.sqlite3"
            initialize(database)
            add_event(database, {
                "source": "Yerel",
                "method": "GET",
                "path": "/urunler",
                "score": 0,
                "decision": "İzin verildi",
                "reasons": ("Belirgin risk göstergesi bulunamadı",),
            })
            self.assertEqual(statistics(database), {"total": 1, "blocked": 0, "allowed": 1})
            self.assertEqual(len(recent_events(database)), 1)

    def test_existing_database_is_migrated_with_ai_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "legacy.sqlite3"
            with closing(sqlite3.connect(database)) as connection, connection:
                connection.execute(
                    """
                    CREATE TABLE inspection_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TEXT NOT NULL DEFAULT '2026-01-01 00:00:00',
                        source TEXT NOT NULL,
                        method TEXT NOT NULL,
                        path TEXT NOT NULL,
                        score INTEGER NOT NULL,
                        decision TEXT NOT NULL,
                        reasons TEXT NOT NULL
                    )
                    """
                )

            initialize(database)
            add_event(database, {
                "source": "Yerel",
                "method": "GET",
                "path": "/urunler",
                "score": 0,
                "decision": "İzin verildi",
                "reasons": ("Belirgin risk göstergesi bulunamadı",),
                "ai_rf_result": "İzin verildi",
                "ai_rf_confidence": 0.9,
            })

            event = recent_events(database)[0]
            self.assertEqual(event["ai_rf_result"], "İzin verildi")
            self.assertEqual(event["ai_rf_confidence"], 0.9)
            self.assertIsNone(event["ai_dl_result"])


if __name__ == "__main__":
    unittest.main()
