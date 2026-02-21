import time
import unittest
from unittest import mock

from tests.test_support import ensure_nacl_for_tests, load_module


ensure_nacl_for_tests()
server = load_module("server_module", "server/server.py")
nacl_signing = __import__("nacl.signing", fromlist=["SigningKey"])


class ServerSendValidationTests(unittest.TestCase):
    def _make_valid_send(self):
        sk = nacl_signing.SigningKey.generate()
        body = b"encrypted-payload"
        sig = sk.sign(body).signature
        return sk, body, sig

    def test_check_rate_allows_within_limit(self):
        server._rate_log.clear()
        for _ in range(server.RATE_LIMIT):
            self.assertTrue(server.check_rate("10.0.0.1"))

    def test_check_rate_rejects_over_limit(self):
        server._rate_log.clear()
        for _ in range(server.RATE_LIMIT):
            server.check_rate("10.0.0.2")
        self.assertFalse(server.check_rate("10.0.0.2"))

    def test_check_rate_resets_after_window(self):
        server._rate_log.clear()
        past = time.time() - server.RATE_WINDOW - 1
        server._rate_log["10.0.0.3"] = [past] * server.RATE_LIMIT
        self.assertTrue(server.check_rate("10.0.0.3"))

    def test_valid_signature_is_accepted(self):
        sk, body, sig = self._make_valid_send()
        vk = nacl_signing.VerifyKey(sk.verify_key.encode())
        vk.verify(body, sig)  # should not raise

    def test_wrong_key_signature_is_rejected(self):
        sk, body, sig = self._make_valid_send()
        other = nacl_signing.SigningKey.generate()
        vk = nacl_signing.VerifyKey(other.verify_key.encode())
        with self.assertRaises(Exception):
            vk.verify(body, sig)

    def test_tampered_body_signature_is_rejected(self):
        sk, body, sig = self._make_valid_send()
        tampered = b"tampered-payload"
        vk = nacl_signing.VerifyKey(sk.verify_key.encode())
        with self.assertRaises(Exception):
            vk.verify(tampered, sig)

    def test_max_ciphertext_constant_exists(self):
        self.assertGreater(server.MAX_CIPHERTEXT, 0)
        self.assertLessEqual(server.MAX_CIPHERTEXT, server.MAX_BODY)


class ServerSafetyTests(unittest.TestCase):
    def test_verify_inbox_auth_accepts_valid_signature(self):
        sk = nacl_signing.SigningKey.generate()
        to_hex = sk.verify_key.encode().hex()
        ts = "1700000000"
        after = "99"
        payload = f"{ts}|{to_hex}|{after}".encode()
        sig = sk.sign(payload).signature.hex()

        with mock.patch.object(server.time, "time", return_value=1700000000):
            self.assertTrue(server.verify_inbox_auth(to_hex, ts, after, sig))

    def test_verify_inbox_auth_rejects_old_or_future_timestamps(self):
        sk = nacl_signing.SigningKey.generate()
        to_hex = sk.verify_key.encode().hex()
        after = "0"

        old_ts = "1699999900"
        old_payload = f"{old_ts}|{to_hex}|{after}".encode()
        old_sig = sk.sign(old_payload).signature.hex()

        future_ts = "1700000200"
        future_payload = f"{future_ts}|{to_hex}|{after}".encode()
        future_sig = sk.sign(future_payload).signature.hex()

        with mock.patch.object(server.time, "time", return_value=1700000000):
            self.assertFalse(server.verify_inbox_auth(to_hex, old_ts, after, old_sig))
            self.assertFalse(server.verify_inbox_auth(to_hex, future_ts, after, future_sig))

    def test_verify_inbox_auth_rejects_invalid_signature(self):
        sk = nacl_signing.SigningKey.generate()
        other = nacl_signing.SigningKey.generate()
        to_hex = sk.verify_key.encode().hex()
        ts = "1700000000"
        after = "55"
        payload = f"{ts}|{to_hex}|{after}".encode()
        sig = other.sign(payload).signature.hex()

        with mock.patch.object(server.time, "time", return_value=1700000000):
            self.assertFalse(server.verify_inbox_auth(to_hex, ts, after, sig))


if __name__ == "__main__":
    unittest.main()
