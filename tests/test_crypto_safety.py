import time
import unittest

from tests.test_support import ensure_nacl_for_tests, load_module


ensure_nacl_for_tests()
client_mail = load_module("client_mail", "client/mail.py")


class CryptoSafetyTests(unittest.TestCase):
    def test_tls_verification_is_enabled(self):
        self.assertEqual(client_mail.TLS.verify_mode, client_mail.ssl.CERT_REQUIRED)
        self.assertTrue(client_mail.TLS.check_hostname)

    def test_encrypt_decrypt_round_trip(self):
        recipient = client_mail.nacl.public.PrivateKey.generate()
        body = client_mail.encrypt_body(recipient.public_key.encode(), b"secret-message")
        plaintext = client_mail.decrypt_body(recipient, body)
        self.assertEqual(plaintext, b"secret-message")

    def test_decrypt_with_wrong_key_fails(self):
        recipient = client_mail.nacl.public.PrivateKey.generate()
        wrong_recipient = client_mail.nacl.public.PrivateKey.generate()
        body = client_mail.encrypt_body(recipient.public_key.encode(), b"do-not-leak")
        with self.assertRaises(Exception):
            client_mail.decrypt_body(wrong_recipient, body)

    def test_ciphertext_tampering_is_detected(self):
        recipient = client_mail.nacl.public.PrivateKey.generate()
        body = client_mail.encrypt_body(recipient.public_key.encode(), b"integrity")
        tampered = bytearray(body)
        tampered[-1] ^= 0x01
        with self.assertRaises(Exception):
            client_mail.decrypt_body(recipient, bytes(tampered))

    def test_decrypt_with_wrong_nonce_fails(self):
        recipient = client_mail.nacl.public.PrivateKey.generate()
        body = client_mail.encrypt_body(recipient.public_key.encode(), b"nonce-check")
        tampered_nonce = bytearray(body)
        tampered_nonce[32] ^= 0x01
        with self.assertRaises(Exception):
            client_mail.decrypt_body(recipient, bytes(tampered_nonce))

    def test_decrypt_with_malformed_nonce_section_fails(self):
        recipient = client_mail.nacl.public.PrivateKey.generate()
        body = client_mail.encrypt_body(recipient.public_key.encode(), b"nonce-length")
        malformed = body[:32] + body[33:]
        with self.assertRaises(Exception):
            client_mail.decrypt_body(recipient, malformed)

    def test_sender_signature_detects_tamper(self):
        sender = client_mail.nacl.signing.SigningKey.generate()
        recipient = client_mail.nacl.public.PrivateKey.generate()
        body = client_mail.encrypt_body(recipient.public_key.encode(), b"auth")
        sig = sender.sign(body).signature

        sender.verify_key.verify(body, sig)

        tampered = bytearray(body)
        tampered[0] ^= 0x01
        with self.assertRaises(Exception):
            sender.verify_key.verify(bytes(tampered), sig)

    def test_inbox_auth_payload_binding(self):
        sender = client_mail.nacl.signing.SigningKey.generate()
        to_hex = sender.verify_key.encode().hex()
        ts = str(int(time.time()))
        after = "1234"
        payload = f"{ts}|{to_hex}|{after}".encode()
        sig = sender.sign(payload).signature.hex()

        server = load_module("server_module_for_binding", "server/server.py")
        self.assertTrue(server.verify_inbox_auth(to_hex, ts, after, sig))
        self.assertFalse(server.verify_inbox_auth(to_hex, ts, "1235", sig))
        self.assertFalse(server.verify_inbox_auth("00" * 32, ts, after, sig))


if __name__ == "__main__":
    unittest.main()
