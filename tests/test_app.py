import json
import csv
from io import StringIO
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_engine import AIPrediction
from app import _format_ai_assessment, create_app
from storage import add_event, recent_events


class AppFlowTests(unittest.TestCase):
    def test_login_rejects_scheme_relative_next_redirect(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_app({
                "TESTING": True,
                "DATABASE": str(Path(directory) / "test.sqlite3"),
                "ADMIN_USERNAME": "admin",
                "ADMIN_PASSWORD": "test-password",
                "ADMIN_PASSWORD_HASH": "",
            })

            for next_url in ("//attacker.example/path", "/\\attacker.example/path"):
                with self.subTest(next_url=next_url):
                    response = app.test_client().post(
                        "/giris",
                        query_string={"next": next_url},
                        data={"username": "admin", "password": "test-password"},
                    )

                    self.assertEqual(response.status_code, 302)
                    self.assertEqual(response.headers["Location"], "/panel")

    def test_ai_assessments_show_normalized_labels_and_confidence(self):
        self.assertEqual(_format_ai_assessment("Engellendi", 0.92), "Anomali (%92)")
        self.assertEqual(_format_ai_assessment("İzin verildi", 0.98), "Normal (%98)")
        self.assertEqual(_format_ai_assessment(None, None), "—")

    def test_logs_show_advisory_confidence_and_spaced_request_target(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_app({
                "TESTING": True,
                "DATABASE": str(Path(directory) / "test.sqlite3"),
            })
            add_event(
                app.config["DATABASE"],
                {
                    "source": "Yerel",
                    "method": "GET",
                    "path": "/index.html",
                    "score": 0,
                    "decision": "İzin verildi",
                    "reasons": ("Test",),
                    "ai_rf_result": "Engellendi",
                    "ai_rf_confidence": 0.92,
                    "ai_dl_result": "İzin verildi",
                    "ai_dl_confidence": 0.98,
                },
            )

            response = app.test_client().get("/gunluk")

            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Anomali (%92)", response.data)
            self.assertIn(b"Normal (%98)", response.data)
            self.assertIn(b"GET /index.html", response.data)
            self.assertIn(b"Advisory Layer", response.data)

    def test_inspection_is_logged_and_dashboard_updates(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_app({
                "TESTING": True,
                "DATABASE": str(Path(directory) / "test.sqlite3"),
            })
            client = app.test_client()

            response = client.post(
                "/incele",
                data={"path": "/urunler", "method": "GET", "user_agent": "TestBrowser/1"},
            )
            self.assertEqual(response.status_code, 200)
            self.assertIn("İzin verildi".encode(), response.data)

            dashboard = client.get("/panel")
            self.assertEqual(dashboard.status_code, 200)
            self.assertIn(b"Toplam inceleme", dashboard.data)
            self.assertIn(b"/urunler", dashboard.data)

            summary = client.get("/api/ozet")
            self.assertEqual(summary.json, {"total": 1, "blocked": 0, "allowed": 1})

    def test_dashboard_shows_validated_model_metrics(self):
        with tempfile.TemporaryDirectory() as directory:
            metrics_path = Path(directory) / "metrics.json"
            metrics_path.write_text(
                json.dumps({
                    "Random Forest": {
                        "accuracy": 0.9,
                        "precision": 0.8,
                        "recall": 0.7,
                        "f1": 0.75,
                        "false_positive_rate": 0.2,
                    }
                }),
                encoding="utf-8",
            )
            app = create_app({
                "TESTING": True,
                "DATABASE": str(Path(directory) / "test.sqlite3"),
                "AI_METRICS_PATH": str(metrics_path),
            })

            response = app.test_client().get("/panel")

            self.assertEqual(response.status_code, 200)
            self.assertIn(b"Random Forest", response.data)
            self.assertIn(b"90.0%", response.data)
            self.assertIn(b"20.0%", response.data)

    def test_local_scenario_inspects_payload_without_sending_or_executing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "test.sqlite3"
            prediction = AIPrediction("Engellendi", 0.9, None, None)
            with patch("app.AIDetector") as detector_factory:
                detector = detector_factory.return_value
                detector.is_available = True
                detector.rf_available = True
                detector.dl_available = False
                detector.predict.return_value = prediction
                app = create_app({
                    "TESTING": True,
                    "DATABASE": str(database),
                })
                client = app.test_client()

                response = client.post(
                    "/simulasyon/gonder",
                    data={"attack_type": "sqli"},
                    follow_redirects=True,
                )

            self.assertEqual(response.status_code, 200)
            self.assertIn(b"SQLi", response.data)
            event = recent_events(database)[0]
            self.assertEqual(event["path"], "/login?user=admin' OR '1'='1")
            self.assertEqual(event["decision"], "Engellendi")
            self.assertIn("SQL Injection", event["reasons"])
            self.assertIn("ağ isteği veya komut çalıştırılmadı", event["reasons"])
            detector.predict.assert_called_once_with(
                "GET",
                "/login",
                "user=admin' OR '1'='1",
            )

    def test_manual_inspection_passes_structured_features_to_ai(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "test.sqlite3"
            prediction = AIPrediction("Engellendi", 0.98, None, None)
            with patch("app.AIDetector") as detector_factory:
                detector = detector_factory.return_value
                detector.is_available = True
                detector.rf_available = True
                detector.dl_available = False
                detector.predict.return_value = prediction
                app = create_app({
                    "TESTING": True,
                    "DATABASE": str(database),
                })

                response = app.test_client().post(
                    "/incele",
                    data={
                        "path": "/urunler",
                        "method": "GET",
                        "query": "category=books",
                        "user_agent": "TestBrowser/1",
                    },
                )

            self.assertEqual(response.status_code, 200)
            event = recent_events(database)[0]
            self.assertEqual(event["decision"], "İzin verildi")
            self.assertEqual(event["ai_rf_result"], "Engellendi")
            detector.predict.assert_called_once_with(
                "GET", "/urunler", "category=books"
            )

    def test_manual_inspection_keeps_rule_result_when_ai_inference_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "test.sqlite3"
            with patch("app.AIDetector") as detector_factory:
                detector = detector_factory.return_value
                detector.is_available = True
                detector.rf_available = True
                detector.dl_available = False
                detector.predict.side_effect = RuntimeError("model unavailable")
                app = create_app({
                    "TESTING": True,
                    "DATABASE": str(database),
                })

                with self.assertLogs("app", level="ERROR"):
                    response = app.test_client().post(
                        "/incele",
                        data={
                            "path": "/urunler",
                            "method": "GET",
                            "user_agent": "TestBrowser/1",
                        },
                    )

            event = recent_events(database)[0]

            self.assertEqual(response.status_code, 200)
            self.assertEqual(event["decision"], "İzin verildi")
            self.assertIsNone(event["ai_rf_result"])
            self.assertIsNone(event["ai_dl_result"])
            detector.predict.assert_called_once_with("GET", "/urunler", "")

    def test_simulation_rejects_unknown_scenario(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_app({
                "TESTING": True,
                "DATABASE": str(Path(directory) / "test.sqlite3"),
            })

            response = app.test_client().post(
                "/simulasyon/gonder",
                data={"attack_type": "unknown"},
            )

            self.assertEqual(response.status_code, 400)

    def test_simulation_page_displays_scenario_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("app.AIDetector") as detector_factory:
                detector_factory.return_value.is_available = False
                app = create_app({
                    "TESTING": True,
                    "DATABASE": str(Path(directory) / "test.sqlite3"),
                })

                response = app.test_client().get("/simulasyon")

            self.assertEqual(response.status_code, 200)
            self.assertIn(b'<option value="sqli">SQLi</option>', response.data)
            self.assertNotIn(b"admin", response.data)

    def test_csv_and_pdf_exports_are_downloadable(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_app({
                "TESTING": True,
                "DATABASE": str(Path(directory) / "test.sqlite3"),
            })
            client = app.test_client()
            client.post(
                "/incele",
                data={"path": "/urunler", "method": "GET", "user_agent": "TestBrowser/1"},
            )
            add_event(
                app.config["DATABASE"],
                {
                    "source": "Yerel",
                    "method": "GET",
                    "path": "=1+1",
                    "score": 0,
                    "decision": "İzin verildi",
                    "reasons": ("Test export",),
                },
            )

            csv_response = client.get("/export/csv")
            csv_text = csv_response.get_data(as_text=True).lstrip("\ufeff")
            exported_rows = list(csv.DictReader(StringIO(csv_text)))
            pdf_response = client.get("/export/pdf")

            self.assertEqual(csv_response.status_code, 200)
            self.assertEqual(csv_response.mimetype, "text/csv")
            self.assertEqual(exported_rows[0]["Yol"], "'=1+1")
            self.assertEqual(exported_rows[1]["Yol"], "/urunler")
            self.assertEqual(pdf_response.status_code, 200)
            self.assertEqual(pdf_response.mimetype, "application/pdf")
            self.assertTrue(pdf_response.data.startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
