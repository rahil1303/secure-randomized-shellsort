
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import pickle
import hashlib

BLOCK_SIZE = 16  # AES block size (bytes)

def SE_SGen() -> bytes:
    """Generate a fresh symmetric key."""
    return get_random_bytes(32)  # AES-256

def SE_SEnc(Ke: bytes, obj) -> bytes:
    """
    Encrypt a Python object:
      - pickle -> pad -> AES-CBC
      - returns iv || ciphertext
    """
    iv = get_random_bytes(BLOCK_SIZE)             # ✅ fixed: get_random_bytes
    cipher = AES.new(Ke, AES.MODE_CBC, iv=iv)
    plaintext = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
    ct = cipher.encrypt(pad(plaintext, BLOCK_SIZE))
    return iv + ct

def SE_SDec(Ke: bytes, data: bytes):
    """
    Decrypt bytes produced by SE_SEnc:
      - split iv || ciphertext -> AES-CBC -> unpad -> unpickle
    """
    iv = data[:BLOCK_SIZE]
    actual_cipher = data[BLOCK_SIZE:]             # ✅ fixed: [BLOCK_SIZE:]
    cipher = AES.new(Ke, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(actual_cipher), BLOCK_SIZE)
    return pickle.loads(pt)

def E_BGen() -> bytes:
    """Generate bitwise encryption key (same as SE key generation)"""
    return get_random_bytes(32)

def E_BEnc(Kb: bytes, bit: int) -> bytes:
    """CPA-secure encryption of a single bit"""
    # Simple approach: encrypt the bit value with random IV
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(Kb, AES.MODE_CBC, iv=iv)
    plaintext = pad(bytes([bit]), BLOCK_SIZE)
    ct = cipher.encrypt(plaintext)
    return iv + ct

def E_BDec(Kb: bytes, encrypted_bit: bytes) -> int:
    """Decrypt single bit"""
    iv = encrypted_bit[:BLOCK_SIZE]
    actual_cipher = encrypted_bit[BLOCK_SIZE:]
    cipher = AES.new(Kb, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(actual_cipher), BLOCK_SIZE)
    return pt[0]  # Return the bit value (0 or 1)

def HGen(Kb: bytes, d: int):
    """
    Generate d hash functions using key Kb.
    Each function maps int → int using SHA-256-based PRF
    """
    def make_hash_fn(i):
        def h(x):
            data = Kb + i.to_bytes(4, 'big') + x.to_bytes(4, 'big')
            digest = hashlib.sha256(data).digest()
            return int.from_bytes(digest, 'big')
        return h

    return [make_hash_fn(i) for i in range(d)]
