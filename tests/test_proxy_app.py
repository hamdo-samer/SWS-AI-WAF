import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import proxy_app
from storage import initialize, recent_events


class ProxyAppTests(unittest.TestCase):
    def test_static_asset_skips_ai_even_with_query_string(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "proxy.sqlite3"
            initialize(database)
            client = proxy_app.app.test_client()
            upstream_response = SimpleNamespace(
                content=b"body { color: red; }",
                status_code=200,
                headers={"Content-Type": "text/css"},
            )

            with (
                patch.object(proxy_app, "DB_PATH", str(database)),
                patch.object(
                    proxy_app.ai_detector,
                    "predict",
                    side_effect=AssertionError("AI should not inspect static assets"),
                ) as predict,
                patch.object(
                    proxy_app.requests,
                    "request",
                    return_value=upstream_response,
                ) as forward_request,
            ):
                response = client.get(
                    "/assets/site.CSS?v=1",
                    headers={"User-Agent": "TestBrowser/1.0"},
                )

            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data, b"body { color: red; }")
            predict.assert_not_called()
            forward_request.assert_called_once()

            event = recent_events(database)[0]
            self.assertIsNone(event["ai_rf_result"])
            self.assertIsNone(event["ai_rf_confidence"])
            self.assertIsNone(event["ai_dl_result"])
            self.assertIsNone(event["ai_dl_confidence"])

    def test_form_encoded_query_attack_is_blocked_before_forwarding(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "proxy.sqlite3"
            initialize(database)
            client = proxy_app.app.test_client()

            with (
                patch.object(proxy_app, "DB_PATH", str(database)),
                patch.object(
                    proxy_app.ai_detector,
                    "predict",
                    return_value=proxy_app.AIPrediction(None, None, None, None),
                ),
                patch.object(proxy_app.requests, "request") as forward_request,
            ):
                response = client.get(
                    "/login?user=admin%27+OR+%271%27%3D%271",
                    headers={"User-Agent": "TestBrowser/1.0"},
                )

            self.assertEqual(response.status_code, 403)
            forward_request.assert_not_called()
            self.assertEqual(recent_events(database)[0]["decision"], "Engellendi")

    def test_form_encoded_body_attack_is_blocked_before_forwarding(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "proxy.sqlite3"
            initialize(database)
            client = proxy_app.app.test_client()

            with (
                patch.object(proxy_app, "DB_PATH", str(database)),
                patch.object(
                    proxy_app.ai_detector,
                    "predict",
                    return_value=proxy_app.AIPrediction(None, None, None, None),
                ),
                patch.object(proxy_app.requests, "request") as forward_request,
            ):
                response = client.post(
                    "/login",
                    data="user=admin%27+OR+%271%27%3D%271",
                    content_type="application/x-www-form-urlencoded",
                    headers={"User-Agent": "TestBrowser/1.0"},
                )

            self.assertEqual(response.status_code, 403)
            forward_request.assert_not_called()

    def test_ai_advisory_failure_does_not_skip_rule_engine_or_forwarding(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "proxy.sqlite3"
            initialize(database)
            client = proxy_app.app.test_client()
            upstream_response = SimpleNamespace(
                content=b"ok",
                status_code=200,
                headers={"Content-Type": "text/plain"},
            )

            with (
                patch.object(proxy_app, "DB_PATH", str(database)),
                patch.object(
                    proxy_app.ai_detector,
                    "predict",
                    side_effect=RuntimeError("model unavailable"),
                ),
                patch.object(
                    proxy_app.requests,
                    "request",
                    return_value=upstream_response,
                ) as forward_request,
            ):
                response = client.get(
                    "/products",
                    headers={"User-Agent": "TestBrowser/1.0"},
                )

            self.assertEqual(response.status_code, 200)
            forward_request.assert_called_once()
            event = recent_events(database)[0]
            self.assertIsNone(event["ai_rf_result"])
            self.assertIsNone(event["ai_rf_confidence"])


if __name__ == "__main__":
    unittest.main()
