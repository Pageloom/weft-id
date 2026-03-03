"""Tests for centralized key derivation."""

import base64
from unittest.mock import patch

from cryptography.fernet import Fernet
from utils.crypto import derive_fernet_key, derive_session_key


class TestDeriveFernetKey:
    """Tests for derive_fernet_key function."""

    def test_returns_valid_fernet_key(self):
        """Derived key can be used to create a Fernet cipher."""
        key = derive_fernet_key(b"test-purpose")
        # Should not raise
        cipher = Fernet(key)
        # Verify roundtrip encryption/decryption
        plaintext = b"hello world"
        assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext

    def test_key_is_32_bytes_base64_encoded(self):
        """Derived key decodes to exactly 32 bytes."""
        key = derive_fernet_key(b"test-purpose")
        raw = base64.urlsafe_b64decode(key)
        assert len(raw) == 32

    def test_different_info_produces_different_keys(self):
        """Different info parameters produce different keys."""
        key_a = derive_fernet_key(b"purpose-a")
        key_b = derive_fernet_key(b"purpose-b")
        assert key_a != key_b

    def test_same_info_produces_same_key(self):
        """Same info parameter produces the same key (deterministic)."""
        key1 = derive_fernet_key(b"same-purpose")
        key2 = derive_fernet_key(b"same-purpose")
        assert key1 == key2

    def test_different_master_secret_produces_different_key(self):
        """Different master secrets produce different derived keys."""
        key1 = derive_fernet_key(b"test-purpose")

        with patch("utils.crypto.settings.SECRET_KEY", "different-master-secret"):
            key2 = derive_fernet_key(b"test-purpose")

        assert key1 != key2

    def test_production_info_parameters_are_unique(self):
        """All production info parameters produce distinct keys."""
        mfa_key = derive_fernet_key(b"mfa-encryption")
        saml_key = derive_fernet_key(b"saml-key-encryption")
        email_key = derive_fernet_key(b"email-verification")

        assert len({mfa_key, saml_key, email_key}) == 3


class TestDeriveSessionKey:
    """Tests for derive_session_key function."""

    def test_returns_hex_string(self):
        """Session key is a valid hex string."""
        key = derive_session_key()
        assert isinstance(key, str)
        # Should be valid hex (no exception)
        bytes.fromhex(key)

    def test_returns_64_char_hex(self):
        """Session key is 64 hex chars (32 bytes)."""
        key = derive_session_key()
        assert len(key) == 64

    def test_deterministic(self):
        """Same master secret produces same session key."""
        key1 = derive_session_key()
        key2 = derive_session_key()
        assert key1 == key2

    def test_differs_from_fernet_keys(self):
        """Session key is distinct from all Fernet-derived keys."""
        session_key_bytes = bytes.fromhex(derive_session_key())
        mfa_key_bytes = base64.urlsafe_b64decode(derive_fernet_key(b"mfa-encryption"))
        assert session_key_bytes != mfa_key_bytes
