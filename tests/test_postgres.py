"""Integration tests against a real PostgreSQL. Skipped unless TEST_DATABASE_URL is set, e.g.

    docker compose up -d
    TEST_DATABASE_URL=postgresql://auth_user:change-me@localhost:5432/auth_db python -m unittest tests.test_postgres
"""
import os
import unittest

from tests.helpers import GOOD_PW, auth_header, make_app, register_and_login

DSN = os.environ.get("TEST_DATABASE_URL")


@unittest.skipUnless(DSN, "TEST_DATABASE_URL not set")
class PostgresIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from app.repository import PostgresRepository
        cls.repo = PostgresRepository(DSN)
        cls.repo.init_schema()

    @classmethod
    def tearDownClass(cls):
        cls.repo.close()

    def setUp(self):
        with self.repo._cur() as cur:
            cur.execute("TRUNCATE sessions, users CASCADE")
        self.c = make_app(self.repo).test_client()

    def test_full_flow(self):
        tokens = register_and_login(self.c, full_name="Pg User")
        h = auth_header(tokens["access_token"])
        self.assertEqual(self.c.get("/auth/me", headers=h).get_json()["user"]["full_name"], "Pg User")
        with self.repo._cur() as cur:
            cur.execute("SELECT password_hash, full_name_enc FROM users")
            row = cur.fetchone()
        self.assertTrue(row["password_hash"].startswith("$2"))
        self.assertNotIn("Pg User", row["full_name_enc"])

        new = self.c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).get_json()
        self.assertEqual(self.c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code, 401)
        self.assertEqual(self.c.get("/auth/me", headers=auth_header(new["access_token"])).status_code, 401)

    def test_duplicate_email_and_lockout(self):
        register_and_login(self.c)
        self.assertEqual(self.c.post("/auth/register", json={"email": "ALICE@example.com", "password": GOOD_PW}).status_code, 409)
        for _ in range(5):
            self.c.post("/auth/login", json={"email": "alice@example.com", "password": "Wrong-Password-1!"})
        self.assertEqual(self.c.post("/auth/login", json={"email": "alice@example.com", "password": GOOD_PW}).status_code, 401)

    def test_sql_injection_strings_are_inert(self):
        r = self.c.post("/auth/login", json={"email": "x@example.com' OR '1'='1", "password": "' OR 1=1 --"})
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main()
