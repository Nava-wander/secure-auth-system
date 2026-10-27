import unittest
from datetime import timedelta

from app import security as sec
from tests.helpers import GOOD_PW, auth_header, make_app, make_config, register_and_login
from tests.memory_repo import MemoryRepository


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.repo = MemoryRepository()
        self.app = make_app(self.repo)
        self.c = self.app.test_client()

    # ---- registration ----
    def test_register_validation(self):
        r = self.c.post("/auth/register", json={"email": "not-an-email", "password": "weak"})
        self.assertEqual(r.status_code, 400)
        d = r.get_json()["details"]
        self.assertIn("email", d)
        self.assertIn("password", d)

    def test_register_success_and_duplicate(self):
        r = self.c.post("/auth/register", json={"email": "Bob@Example.com ", "password": GOOD_PW})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()["user"]
        self.assertEqual(body["email"], "bob@example.com")
        self.assertNotIn("password", str(r.get_json()))
        r = self.c.post("/auth/register", json={"email": "bob@example.com", "password": GOOD_PW})
        self.assertEqual(r.status_code, 409)

    def test_password_stored_as_bcrypt_and_pii_encrypted(self):
        self.c.post("/auth/register", json={"email": "c@example.com", "password": GOOD_PW,
                                            "full_name": "Carol Danvers", "phone": "+91 98765 43210"})
        u = self.repo.get_user_by_email("c@example.com")
        self.assertTrue(u["password_hash"].startswith("$2"))
        self.assertNotIn(GOOD_PW, u["password_hash"])
        self.assertNotIn("Carol", u["full_name_enc"])
        self.assertNotIn("98765", u["phone_enc"])
        t = register_and_login(self.c, "d@example.com")["access_token"]
        self.assertIsNone(self.c.get("/auth/me", headers=auth_header(t)).get_json()["user"]["full_name"])

    def test_bad_bodies(self):
        for path in ("/auth/register", "/auth/login", "/auth/refresh"):
            self.assertEqual(self.c.post(path, data="not json", content_type="text/plain").status_code, 400)
            self.assertEqual(self.c.post(path, json=["x"]).status_code, 400)

    # ---- login ----
    def test_login_flow_and_me(self):
        tokens = register_and_login(self.c, full_name="Alice A")
        self.assertEqual(tokens["token_type"], "Bearer")
        me = self.c.get("/auth/me", headers=auth_header(tokens["access_token"]))
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.get_json()["user"]["full_name"], "Alice A")

    def test_login_failures_are_indistinguishable(self):
        register_and_login(self.c)
        wrong = self.c.post("/auth/login", json={"email": "alice@example.com", "password": "Wrong-Password-1!"})
        unknown = self.c.post("/auth/login", json={"email": "nobody@example.com", "password": "Wrong-Password-1!"})
        self.assertEqual((wrong.status_code, unknown.status_code), (401, 401))
        self.assertEqual(wrong.get_json(), unknown.get_json())

    def test_lockout_after_repeated_failures(self):
        register_and_login(self.c)
        for _ in range(5):
            self.c.post("/auth/login", json={"email": "alice@example.com", "password": "Wrong-Password-1!"})
        r = self.c.post("/auth/login", json={"email": "alice@example.com", "password": GOOD_PW})
        self.assertEqual(r.status_code, 401)               # locked even with the right password
        self.repo.users[next(iter(self.repo.users))]["locked_until"] = sec.utcnow() - timedelta(seconds=1)
        r = self.c.post("/auth/login", json={"email": "alice@example.com", "password": GOOD_PW})
        self.assertEqual(r.status_code, 200)               # lock expired

    # ---- JWT handling ----
    def test_protected_routes_reject_bad_tokens(self):
        t = register_and_login(self.c)["access_token"]
        self.assertEqual(self.c.get("/auth/me").status_code, 401)
        self.assertEqual(self.c.get("/auth/me", headers={"Authorization": "Basic abc"}).status_code, 401)
        self.assertEqual(self.c.get("/auth/me", headers=auth_header("garbage")).status_code, 401)
        self.assertEqual(self.c.get("/auth/me", headers=auth_header(t[:-3] + "abc")).status_code, 401)
        r = self.c.get("/auth/me")
        self.assertIn("Bearer", r.headers["WWW-Authenticate"])

    def test_expired_access_token(self):
        app = make_app(MemoryRepository())
        c = app.test_client()
        register_and_login(c)
        # PyJWT leeway is 5s, so forge a token issued 30 minutes ago instead of sleeping
        ext = app.extensions["auth"]
        sid = next(iter(ext.repo.sessions)); uid = next(iter(ext.repo.users))
        old, _ = sec.create_access_token(ext.cfg, uid, sid, now=sec.utcnow() - timedelta(minutes=30))
        r = c.get("/auth/me", headers=auth_header(old))
        self.assertEqual(r.status_code, 401)
        self.assertIn("expired", r.get_json()["message"].lower())

    # ---- sessions ----
    def test_logout_invalidates_access_token_immediately(self):
        tokens = register_and_login(self.c)
        h = auth_header(tokens["access_token"])
        self.assertEqual(self.c.post("/auth/logout", headers=h).status_code, 200)
        self.assertEqual(self.c.get("/auth/me", headers=h).status_code, 401)
        self.assertEqual(self.c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code, 401)

    def test_refresh_rotation(self):
        tokens = register_and_login(self.c)
        r = self.c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        self.assertEqual(r.status_code, 200)
        new = r.get_json()
        self.assertNotEqual(new["refresh_token"], tokens["refresh_token"])
        self.assertEqual(self.c.get("/auth/me", headers=auth_header(new["access_token"])).status_code, 200)
        # old access token's session was rotated away
        self.assertEqual(self.c.get("/auth/me", headers=auth_header(tokens["access_token"])).status_code, 401)

    def test_refresh_token_reuse_revokes_whole_family(self):
        tokens = register_and_login(self.c)
        new = self.c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).get_json()
        replay = self.c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})  # attacker replays
        self.assertEqual(replay.status_code, 401)
        self.assertEqual(self.c.get("/auth/me", headers=auth_header(new["access_token"])).status_code, 401)
        self.assertEqual(self.c.post("/auth/refresh", json={"refresh_token": new["refresh_token"]}).status_code, 401)

    def test_unknown_and_expired_refresh_tokens(self):
        self.assertEqual(self.c.post("/auth/refresh", json={"refresh_token": "x" * 50}).status_code, 401)
        tokens = register_and_login(self.c)
        for s in self.repo.sessions.values():
            s["expires_at"] = sec.utcnow() - timedelta(seconds=1)
        self.assertEqual(self.c.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}).status_code, 401)

    def test_logout_all_and_session_listing(self):
        t1 = register_and_login(self.c)
        t2 = self.c.post("/auth/login", json={"email": "alice@example.com", "password": GOOD_PW}).get_json()
        h2 = auth_header(t2["access_token"])
        sessions = self.c.get("/auth/sessions", headers=h2).get_json()["sessions"]
        self.assertEqual(len(sessions), 2)
        self.assertEqual(sum(s["current"] for s in sessions), 1)
        other = next(s for s in sessions if not s["current"])
        self.assertEqual(self.c.delete(f"/auth/sessions/{other['id']}", headers=h2).status_code, 200)
        self.assertEqual(self.c.get("/auth/me", headers=auth_header(t1["access_token"])).status_code, 401)
        self.assertEqual(self.c.delete("/auth/sessions/not-a-uuid", headers=h2).status_code, 404)
        self.assertEqual(self.c.post("/auth/logout-all", headers=h2).status_code, 200)
        self.assertEqual(self.c.get("/auth/me", headers=h2).status_code, 401)

    def test_cannot_revoke_someone_elses_session(self):
        register_and_login(self.c, "a@example.com")
        victim_sid = next(iter(self.repo.sessions))
        t = register_and_login(self.c, "b@example.com")["access_token"]
        r = self.c.delete(f"/auth/sessions/{victim_sid}", headers=auth_header(t))
        self.assertEqual(r.status_code, 404)
        self.assertIsNone(self.repo.sessions[victim_sid]["revoked_at"])

    # ---- profile / password ----
    def test_update_profile_validation(self):
        t = register_and_login(self.c)["access_token"]
        h = auth_header(t)
        r = self.c.patch("/auth/me", headers=h, json={"full_name": "New Name", "phone": "+1 (555) 123-4567"})
        self.assertEqual(r.get_json()["user"]["full_name"], "New Name")
        self.assertEqual(self.c.patch("/auth/me", headers=h, json={"phone": "abc"}).status_code, 400)
        r = self.c.patch("/auth/me", headers=h, json={"email": "evil@example.com", "is_active": False})
        self.assertEqual(r.status_code, 200)               # mass-assignment attempt is ignored
        self.assertEqual(r.get_json()["user"]["email"], "alice@example.com")

    def test_change_password(self):
        tokens = register_and_login(self.c)
        h = auth_header(tokens["access_token"])
        self.assertEqual(self.c.post("/auth/change-password", headers=h,
                         json={"current_password": "nope", "new_password": "Another-Strong-Pass-1"}).status_code, 403)
        self.assertEqual(self.c.post("/auth/change-password", headers=h,
                         json={"current_password": GOOD_PW, "new_password": "weak"}).status_code, 400)
        self.assertEqual(self.c.post("/auth/change-password", headers=h,
                         json={"current_password": GOOD_PW, "new_password": "Another-Strong-Pass-1"}).status_code, 200)
        self.assertEqual(self.c.get("/auth/me", headers=h).status_code, 401)           # sessions revoked
        self.assertEqual(self.c.post("/auth/login", json={"email": "alice@example.com", "password": GOOD_PW}).status_code, 401)
        self.assertEqual(self.c.post("/auth/login", json={"email": "alice@example.com", "password": "Another-Strong-Pass-1"}).status_code, 200)

    def test_deactivated_user_cannot_use_token(self):
        t = register_and_login(self.c)["access_token"]
        next(iter(self.repo.users.values()))["is_active"] = False
        self.assertEqual(self.c.get("/auth/me", headers=auth_header(t)).status_code, 401)

    # ---- platform hardening ----
    def test_security_headers_and_error_shape(self):
        r = self.c.get("/health")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertIn("max-age", r.headers["Strict-Transport-Security"])
        self.assertEqual(self.c.get("/nope").get_json()["error"], "not_found")
        self.assertEqual(self.c.post("/auth/register", data="x" * 20000, content_type="application/json").status_code, 413)

    def test_rate_limiting(self):
        c = make_app(MemoryRepository(), rate_limit_per_minute=3).test_client()
        codes = [c.post("/auth/login", json={"email": "a@example.com", "password": "x"}).status_code for _ in range(5)]
        self.assertEqual(codes, [401, 401, 401, 429, 429])
        self.assertEqual(c.post("/auth/login", json={}).headers.get("Retry-After"), "60")

    def test_server_errors_do_not_leak(self):
        class Boom(MemoryRepository):
            def get_user_by_email(self, email): raise RuntimeError("secret db detail")
        r = make_app(Boom()).test_client().post("/auth/login", json={"email": "a@example.com", "password": "x"})
        self.assertEqual(r.status_code, 500)
        self.assertNotIn("secret", r.get_data(as_text=True))

    def test_config_validation(self):
        with self.assertRaises(ValueError):
            make_app(MemoryRepository(), secret_key="short")


if __name__ == "__main__":
    unittest.main()
