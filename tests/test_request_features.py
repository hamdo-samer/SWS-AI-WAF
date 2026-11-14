import unittest

from request_features import format_request_text


class RequestFeatureTests(unittest.TestCase):
    def test_features_use_normalized_url_including_query(self):
        request_text = format_request_text(
            "GET",
            "http://example.test/products?category=books HTTP/1.1",
        )

        self.assertEqual(
            request_text,
            "Method: GET\nURL: /products?category=books\n"
            "LEN:2 SPEC:0 SQL:0 JS:0",
        )

    def test_attack_markers_are_added_as_features(self):
        request_text = format_request_text(
            "GET",
            "/login",
            "user=admin' OR '1'='1&q=<ScRiPt>alert(1)</ScRiPt>",
        )

        self.assertIn("SQL:1", request_text)
        self.assertIn("JS:1", request_text)


if __name__ == "__main__":
    unittest.main()
