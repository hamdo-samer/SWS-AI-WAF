import tempfile
import unittest
import re
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
        protected_pages = (
            "/",
            "/panel",
            "/gunluk",
            "/hakkinda",
            "/simulasyon",
            "/api/ozet",
            "/export/csv",
            "/export/pdf",
        )
        for path in protected_pages:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 302)
                self.assertIn("/giris", response.headers["Location"])

        for path, data in (
            ("/incele", {"path": "/", "method": "GET"}),
            ("/simulasyon/gonder", {"attack_type": "sqli"}),
            ("/cikis", {}),
        ):
            with self.subTest(path=path):
                response = self.client.post(path, data=data)
                self.assertEqual(response.status_code, 302)
                self.assertIn("/giris", response.headers["Location"])

        login_page = self.client.get("/giris")
        self.assertEqual(login_page.status_code, 200)
        self.assertNotIn(b"Kontrol paneli", login_page.data)
        self.assertIn(b"Y\xc3\xb6netici giri\xc5\x9fi", login_page.data)
        self.assertEqual(self.client.get("/saglik").status_code, 200)
        static_response = self.client.get("/static/style.css")
        self.assertEqual(static_response.status_code, 200)
        static_response.close()

    def test_login_and_dashboard_access(self):
        protected_response = self.client.get("/hakkinda?from=menu")
        self.assertEqual(protected_response.status_code, 302)
        login_page = self.client.get(protected_response.headers["Location"])
        self.assertEqual(login_page.status_code, 200)

        form_action = re.search(
            r'<form method="post" action="([^"]+)"',
            login_page.get_data(as_text=True),
        ).group(1)
        with self.client.session_transaction() as session:
            csrf_token = session["csrf_token"]
        response = self.client.post(
            form_action,
            data={
                "username": "admin",
                "password": "Strong-Test-Password",
                "csrf_token": csrf_token,
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/hakkinda?from=menu")

        protected_pages = (
            "/",
            "/panel",
            "/gunluk",
            "/hakkinda",
            "/simulasyon",
            "/api/ozet",
            "/export/csv",
            "/export/pdf",
        )
        for path in protected_pages:
            with self.subTest(path=path):
                page = self.client.get(path)
                self.assertEqual(page.status_code, 200)

        dashboard = self.client.get("/panel")
        self.assertIn(b"Kontrol paneli", dashboard.data)
        self.assertIn(b"\xc3\x87\xc4\xb1k\xc4\xb1\xc5\x9f", dashboard.data)

    def test_security_headers_are_added(self):
        response = self.client.get("/")
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_clean_request_is_allowed(self):
        self.login()
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
        self.login()
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
        self.login()
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
