import unittest
from datetime import timedelta

import jwt
from cryptography.fernet import Fernet

from tests.helpers import make_config
from app import security as sec


class PasswordTests(unittest.TestCase):
    def test_hash_and_verify(self):
        h = sec.hash_password("Correct-Horse-Battery-9", 4)
        self.assertTrue(h.startswith("$2"))
        self.assertTrue(sec.verify_password("Correct-Horse-Battery-9", h))
        self.assertFalse(sec.verify_password("correct-horse-battery-9", h))
        self.assertNotEqual(h, sec.hash_password("Correct-Horse-Battery-9", 4))  # unique salts

    def test_long_passwords_not_truncated(self):
        base = "A1!" + "x" * 80
        h = sec.hash_password(base + "one", 4)
        self.assertFalse(sec.verify_password(base + "two", h))  # differs only after byte 72

    def test_policy(self):
        self.assertEqual(sec.password_problems("Correct-Horse-Battery-9", "a@b.com"), [])
        for bad in ("short1A!", "alllowercaseletters", "Password123456!", "x" * 129, None):
            self.assertTrue(sec.password_problems(bad), bad)
        self.assertTrue(sec.password_problems("alice-Secret-77!", "alice@example.com"))

    def test_rehash_detection(self):
        self.assertTrue(sec.needs_rehash(sec.hash_password("x", 4), 12))
        self.assertFalse(sec.needs_rehash(sec.hash_password("x", 4), 4))


class JwtTests(unittest.TestCase):
    def setUp(self):
        self.cfg = make_config()

    def test_roundtrip(self):
        tok, _ = sec.create_access_token(self.cfg, "u1", "s1")
        c = sec.decode_access_token(self.cfg, tok)
        self.assertEqual((c["sub"], c["sid"], c["typ"]), ("u1", "s1", "access"))

    def test_expired(self):
        old = sec.utcnow() - timedelta(hours=2)
        tok, _ = sec.create_access_token(self.cfg, "u1", "s1", now=old)
        with self.assertRaises(jwt.ExpiredSignatureError):
            sec.decode_access_token(self.cfg, tok)

    def test_tampered_and_wrong_key(self):
        tok, _ = sec.create_access_token(self.cfg, "u1", "s1")
        head, body, sig = tok.split(".")
        with self.assertRaises(jwt.InvalidTokenError):
            sec.decode_access_token(self.cfg, f"{head}.{body}.{sig[:-2]}AA")
        with self.assertRaises(jwt.InvalidTokenError):
            sec.decode_access_token(make_config(secret_key="z" * 48), tok)

    def test_alg_none_rejected(self):
        forged = jwt.encode({"sub": "u1", "sid": "s1"}, key=None, algorithm="none")
        with self.assertRaises(jwt.InvalidTokenError):
            sec.decode_access_token(self.cfg, forged)

    def test_wrong_audience_issuer_and_type(self):
        tok, _ = sec.create_access_token(make_config(jwt_audience="other"), "u1", "s1")
        with self.assertRaises(jwt.InvalidTokenError):
            sec.decode_access_token(self.cfg, tok)
        now = sec.utcnow()
        refresh_like = jwt.encode({"iss": self.cfg.jwt_issuer, "aud": self.cfg.jwt_audience, "typ": "refresh",
                                   "sub": "u", "sid": "s", "jti": "j", "iat": now, "nbf": now,
                                   "exp": now + timedelta(minutes=5)}, self.cfg.secret_key, algorithm="HS256")
        with self.assertRaises(jwt.InvalidTokenError):
            sec.decode_access_token(self.cfg, refresh_like)


class EncryptionTests(unittest.TestCase):
    def test_roundtrip_and_none(self):
        enc = sec.FieldEncryptor([Fernet.generate_key().decode()])
        token = enc.encrypt("Alice Smith")
        self.assertNotIn("Alice", token)
        self.assertEqual(enc.decrypt(token), "Alice Smith")
        self.assertIsNone(enc.encrypt(None))
        self.assertIsNone(enc.decrypt("garbage"))

    def test_key_rotation(self):
        old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
        token = sec.FieldEncryptor([old]).encrypt("secret")
        rotated = sec.FieldEncryptor([new, old])           # new key first, old still decrypts
        self.assertEqual(rotated.decrypt(token), "secret")
        self.assertIsNone(sec.FieldEncryptor([new]).decrypt(token))


class LockoutTests(unittest.TestCase):
    def test_state_machine(self):
        now, locked, attempts = sec.utcnow(), None, 0
        for _ in range(5):
            attempts, locked = sec.next_lock_state(attempts, locked, now, 5, 15)
        self.assertIsNotNone(locked)
        later = now + timedelta(minutes=16)                # lock expired -> counter restarts
        attempts, locked = sec.next_lock_state(attempts, locked, later, 5, 15)
        self.assertEqual((attempts, locked), (1, None))


if __name__ == "__main__":
    unittest.main()
