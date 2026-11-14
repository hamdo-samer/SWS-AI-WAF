import json
import csv
from io import StringIO
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_engine import AIPrediction
from app import create_app
from storage import add_event, recent_events


class AppFlowTests(unittest.TestCase):
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
            self.assertIn(
                b'<option value="sqli">SQL Injection (SQLi)</option>',
                response.data,
            )
            self.assertIn(b'<option value="no_ua">', response.data)
            self.assertNotIn(b"admin", response.data)

    def test_missing_user_agent_scenario_is_logged_as_a_local_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "test.sqlite3"
            with patch("app.AIDetector") as detector_factory:
                detector_factory.return_value.is_available = False
                app = create_app({
                    "TESTING": True,
                    "DATABASE": str(database),
                })

            response = app.test_client().post(
                "/simulasyon/gonder",
                data={"attack_type": "no_ua"},
                follow_redirects=True,
            )

            self.assertEqual(response.status_code, 200)
            event = recent_events(database)[0]
            self.assertEqual(event["path"], "/products")
            self.assertEqual(event["score"], 10)
            self.assertEqual(event["decision"], "İzin verildi")
            self.assertIn("Tarayıcı bilgisi bulunamadı", event["reasons"])

    def test_long_path_scenario_logs_length_signal_without_claiming_a_block(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "test.sqlite3"
            with patch("app.AIDetector") as detector_factory:
                detector_factory.return_value.is_available = False
                app = create_app({
                    "TESTING": True,
                    "DATABASE": str(database),
                })

            response = app.test_client().post(
                "/simulasyon/gonder",
                data={"attack_type": "long_path"},
                follow_redirects=True,
            )

            self.assertEqual(response.status_code, 200)
            event = recent_events(database)[0]
            self.assertEqual(len(event["path"]), 601)
            self.assertEqual(event["score"], 20)
            self.assertEqual(event["decision"], "İzin verildi")
            self.assertIn("İstek yolu beklenenden uzun", event["reasons"])

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
