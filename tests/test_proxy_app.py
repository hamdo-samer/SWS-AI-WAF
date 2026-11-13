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
            self.assertEqual(event["ai_rf_result"], "İzin verildi")
            self.assertEqual(event["ai_rf_confidence"], 1.0)
            self.assertEqual(event["ai_dl_result"], "İzin verildi")
            self.assertEqual(event["ai_dl_confidence"], 1.0)


if __name__ == "__main__":
    unittest.main()
