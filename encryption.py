"""
Client-side encryption utilities.

This module provides:
- SecureEncryption: Fernet-based authenticated encryption for integer values.
- SimpleEncryption: XOR-based encryption for quick demos/tests (not secure).

The server should treat ciphertexts as opaque bytes and must not perform
encryption/decryption operations.
"""

from __future__ import annotations

import struct
from cryptography.fernet import Fernet


class SecureEncryption:
    """
    Fernet-based authenticated encryption for non-negative integers.

    Notes:
      - Fernet uses randomized encryption (ciphertexts are not linkable by equality).
      - Integers are packed to a fixed-width big-endian byte representation.
    """

    def __init__(self, key: bytes | None = None):
        self.key = key if key is not None else Fernet.generate_key()
        self.cipher = Fernet(self.key)

    def encrypt(self, position: int) -> bytes:
        """Encrypt a non-negative integer."""
        if position < 0:
            raise ValueError("position must be non-negative")
        position_bytes = struct.pack(">I", position)  # 32-bit unsigned
        return self.cipher.encrypt(position_bytes)

    def decrypt(self, encrypted_data: bytes) -> int:
        """Decrypt ciphertext into the original integer."""
        decrypted_bytes = self.cipher.decrypt(encrypted_data)
        return struct.unpack(">I", decrypted_bytes)[0]

    def get_key(self) -> bytes:
        """Return the raw Fernet key (caller is responsible for keeping it secret)."""
        return self.key


class SimpleEncryption:
    """
    XOR-based encryption for demos/tests.

    This is not cryptographically secure and should not be used in adversarial
    settings. It is useful for local debugging when you want int-friendly
    ciphertexts.
    """

    def __init__(self, key: int | None = None):
        import random
        self.key = int(key) if key is not None else random.getrandbits(63)

    def encrypt(self, value: int) -> int:
        return int(value) ^ self.key

    def decrypt(self, encrypted_value: int) -> int:
        return int(encrypted_value) ^ self.key


if __name__ == "__main__":
    # Minimal sanity checks
    simple = SimpleEncryption()
    v = 42
    assert simple.decrypt(simple.encrypt(v)) == v

    secure = SecureEncryption()
    pos = 12345
    assert secure.decrypt(secure.encrypt(pos)) == pos

    print("encryption module: OK")
