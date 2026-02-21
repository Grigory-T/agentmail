import importlib.util
import os
import sys
import types


def project_root():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load_module(name, relative_path):
    path = os.path.join(project_root(), relative_path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def ensure_nacl_for_tests():
    try:
        import nacl  # noqa: F401
        return
    except ModuleNotFoundError:
        pass

    # Test-only fallback for environments where PyNaCl is unavailable.
    import hashlib
    import secrets
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    nacl_mod = types.ModuleType("nacl")
    signing_mod = types.ModuleType("nacl.signing")
    public_mod = types.ModuleType("nacl.public")
    utils_mod = types.ModuleType("nacl.utils")
    hash_mod = types.ModuleType("nacl.hash")
    bindings_mod = types.ModuleType("nacl.bindings")
    encoding_mod = types.ModuleType("nacl.encoding")
    exceptions_mod = types.ModuleType("nacl.exceptions")

    class RawEncoder:
        pass

    class _VerifyKey:
        def __init__(self, key_bytes):
            self._vk = ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

        def encode(self):
            return self._vk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

        def verify(self, message, signature):
            self._vk.verify(signature, message)
            return message

    class _Signed:
        def __init__(self, signature):
            self.signature = signature

    class SigningKey:
        def __init__(self, key_bytes):
            self._sk = ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)
            self.verify_key = _VerifyKey(
                self._sk.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )

        @classmethod
        def generate(cls):
            sk = ed25519.Ed25519PrivateKey.generate()
            raw = sk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            return cls(raw)

        def encode(self):
            return self._sk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )

        def sign(self, data):
            return _Signed(self._sk.sign(data))

    class VerifyKey(_VerifyKey):
        pass

    class PublicKey:
        def __init__(self, key_bytes):
            self._pk = x25519.X25519PublicKey.from_public_bytes(key_bytes)

        def encode(self):
            return self._pk.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

    class PrivateKey:
        def __init__(self, key_bytes):
            self._sk = x25519.X25519PrivateKey.from_private_bytes(key_bytes)
            self.public_key = PublicKey(
                self._sk.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )

        @classmethod
        def generate(cls):
            sk = x25519.X25519PrivateKey.generate()
            raw = sk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
            return cls(raw)

        def encode(self):
            return self._sk.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )

    def random_bytes(n):
        return secrets.token_bytes(n)

    def blake2b(data, digest_size=32, encoder=None):
        digest = hashlib.blake2b(data, digest_size=digest_size).digest()
        if encoder is None or encoder is RawEncoder:
            return digest
        return encoder.encode(digest)

    def crypto_scalarmult(private_bytes, public_bytes):
        sk = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        pk = x25519.X25519PublicKey.from_public_bytes(public_bytes)
        return sk.exchange(pk)

    def aead_encrypt(plaintext, aad, nonce, key):
        return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)

    def aead_decrypt(ciphertext, aad, nonce, key):
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)

    signing_mod.SigningKey = SigningKey
    signing_mod.VerifyKey = VerifyKey
    public_mod.PrivateKey = PrivateKey
    public_mod.PublicKey = PublicKey
    utils_mod.random = random_bytes
    hash_mod.blake2b = blake2b
    bindings_mod.crypto_scalarmult = crypto_scalarmult
    bindings_mod.crypto_aead_chacha20poly1305_ietf_encrypt = aead_encrypt
    bindings_mod.crypto_aead_chacha20poly1305_ietf_decrypt = aead_decrypt
    encoding_mod.RawEncoder = RawEncoder
    exceptions_mod.InvalidSignature = InvalidSignature

    nacl_mod.signing = signing_mod
    nacl_mod.public = public_mod
    nacl_mod.utils = utils_mod
    nacl_mod.hash = hash_mod
    nacl_mod.bindings = bindings_mod
    nacl_mod.encoding = encoding_mod
    nacl_mod.exceptions = exceptions_mod

    sys.modules["nacl"] = nacl_mod
    sys.modules["nacl.signing"] = signing_mod
    sys.modules["nacl.public"] = public_mod
    sys.modules["nacl.utils"] = utils_mod
    sys.modules["nacl.hash"] = hash_mod
    sys.modules["nacl.bindings"] = bindings_mod
    sys.modules["nacl.encoding"] = encoding_mod
    sys.modules["nacl.exceptions"] = exceptions_mod
