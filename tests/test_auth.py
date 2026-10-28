import re
import sqlite3
import tempfile
import unittest
from pathlib import Path
from contextlib import closing

import app


class AuthenticationFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        app.ROOT = Path(self.temp.name)
        app.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = app.app.test_client()

    def tearDown(self):
        self.temp.cleanup()

    def token(self):
        page = self.client.get("/").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

    def test_register_hash_login_and_logout(self):
        token = self.token()
        response = self.client.post("/register", data={"email": "learner@example.test", "password": "A-long-test-password-123", "csrf_token": token})
        self.assertEqual(response.status_code, 302)
        with closing(sqlite3.connect(Path(self.temp.name) / "instance" / "users.sqlite3")) as db:
            stored = db.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotIn("A-long-test-password-123", stored)
        self.assertEqual(self.client.get("/").status_code, 200)
        token = self.token()
        self.client.post("/logout", data={"csrf_token": token})
        token = self.token()
        response = self.client.post("/login", data={"email": "learner@example.test", "password": "A-long-test-password-123", "csrf_token": token})
        self.assertEqual(response.status_code, 302)
        self.assertIn(b"Signed in as learner@example.test", self.client.get("/").data)

    def test_rejects_missing_csrf_and_short_password(self):
        self.assertEqual(self.client.post("/register", data={"email": "a@example.test", "password": "short"}).status_code, 400)
        token = self.token()
        self.assertEqual(self.client.post("/register", data={"email": "a@example.test", "password": "short", "csrf_token": token}).status_code, 400)


if __name__ == "__main__":
    unittest.main()

