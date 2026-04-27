import base64
import hashlib
import os

import keyring
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .conf import KEYRING_SERVICE, KEYRING_KEY_NAME

_fernet = None


def get_fernet() -> Fernet:
    """Retrieve the Fernet instance, creating and persisting a key if none exists."""
    global _fernet
    if _fernet is not None:
        return _fernet
    key_str = keyring.get_password(KEYRING_SERVICE, KEYRING_KEY_NAME)
    if key_str is None:
        key = Fernet.generate_key()
        keyring.set_password(KEYRING_SERVICE, KEYRING_KEY_NAME, key.decode())
        key_str = key.decode()
    _fernet = Fernet(key_str.encode())
    return _fernet


def encrypt(data: str) -> str:
    """Encrypt a plaintext string using Fernet symmetric encryption."""
    return get_fernet().encrypt(data.encode()).decode()


def decrypt(data: str) -> str:
    """Decrypt a Fernet-encrypted string."""
    return get_fernet().decrypt(data.encode()).decode()


def hash_password(password: str) -> str:
    """Derive a secure hash of a password using Scrypt KDF.

    Returns a base64-encoded string containing the random salt (16 bytes)
    concatenated with the derived key (32 bytes).
    """
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    key = kdf.derive(password.encode())
    return base64.b64encode(salt + key).decode()


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored Scrypt hash."""
    try:
        data = base64.b64decode(stored_hash.encode())
        salt = data[:16]
        stored_key = data[16:]
        kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
        kdf.verify(password.encode(), stored_key)
        return True
    except Exception:
        return False


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a token string."""
    return hashlib.sha256(token.encode()).hexdigest()
