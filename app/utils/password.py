from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password using Argon2."""
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a password against its hash. Returns True if valid, False otherwise."""
    try:
        _hasher.verify(password_hash, password)
        return True
    except VerifyMismatchError:
        return False
