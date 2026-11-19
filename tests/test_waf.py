import tempfile
import unittest
from pathlib import Path

from app import create_app


class ProductionHardeningTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.database = str(Path(self.directory.name) / "waf.sqlite3")
        self.app = create_app({
            "TESTING": False,
            "DATABASE": self.database,
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "Strong-Test-Password",
            "ADMIN_PASSWORD_HASH": "",
            "CSRF_ENABLED": True,
            "SECRET_KEY": "test-only-secret-key",
        })
        self.app.config["SESSION_COOKIE_SECURE"] = False
        self.client = self.app.test_client()

    def tearDown(self):
        self.directory.cleanup()

    def _csrf_token(self, path="/giris"):
        self.client.get(path)
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def login(self):
        token = self._csrf_token()
        return self.client.post(
            "/giris",
            data={
                "username": "admin",
                "password": "Strong-Test-Password",
                "csrf_token": token,
            },
            follow_redirects=False,
        )

    def test_dashboard_requires_authentication(self):
        response = self.client.get("/panel")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/giris", response.headers["Location"])

    def test_login_and_dashboard_access(self):
        response = self.login()
        self.assertEqual(response.status_code, 302)
        dashboard = self.client.get("/panel")
        self.assertEqual(dashboard.status_code, 200)

    def test_security_headers_are_added(self):
        response = self.client.get("/")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_clean_request_is_allowed(self):
        token = self._csrf_token("/")
        response = self.client.post(
            "/incele",
            data={
                "path": "/products",
                "method": "GET",
                "query": "category=books",
                "user_agent": "TestBrowser/1.0",
                "csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("İzin verildi".encode(), response.data)

    def test_sqli_is_blocked(self):
        token = self._csrf_token("/")
        response = self.client.post(
            "/incele",
            data={
                "path": "/login",
                "method": "POST",
                "query": "user=admin' OR '1'='1",
                "user_agent": "TestBrowser/1.0",
                "csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Engellendi".encode(), response.data)

    def test_xss_is_blocked_after_normalization(self):
        token = self._csrf_token("/")
        response = self.client.post(
            "/incele",
            data={
                "path": "/search",
                "method": "GET",
                "query": "q=%253Cscript%253Ealert%281%29%253C%252Fscript%253E",
                "user_agent": "TestBrowser/1.0",
                "csrf_token": token,
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Engellendi".encode(), response.data)


if __name__ == "__main__":
    unittest.main()
