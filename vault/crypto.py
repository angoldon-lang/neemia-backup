"""Cryptographic primitives for the vault.

Design (see docs/SECURITY.md):
  passphrase --scrypt--> KEK --AES-256-GCM--> wraps a random 256-bit data key (DK)
  DK encrypts every record with AES-256-GCM (random 96-bit nonce, AAD binds the
  ciphertext to its row). A subkey derived with HKDF from DK is used for HMAC
  checksums so that stored checksums never leak plaintext hashes.
Changing the passphrase only re-wraps DK; records are not re-encrypted.
"""
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DEFAULT_KDF = {"n": 2**15, "r": 8, "p": 1}
MIN_PASSPHRASE = 10


class WrongPassphrase(Exception):
    pass


class CorruptRecord(Exception):
    pass


def derive_kek(passphrase: str, salt: bytes, kdf: dict) -> bytes:
    return Scrypt(salt=salt, length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]).derive(
        passphrase.encode("utf-8")
    )


def seal(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def unseal(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], aad)
    except InvalidTag as e:
        raise CorruptRecord("authentication failed") from e


def new_wrapped_key(passphrase: str, kdf: dict | None = None):
    kdf = kdf or DEFAULT_KDF
    salt = os.urandom(16)
    dk = os.urandom(32)
    wrapped = seal(derive_kek(passphrase, salt, kdf), dk, b"awv-dk")
    return dk, {"salt": salt.hex(), "kdf": kdf, "wrapped": wrapped.hex()}


def unwrap_key(passphrase: str, header: dict) -> bytes:
    kek = derive_kek(passphrase, bytes.fromhex(header["salt"]), header["kdf"])
    try:
        return unseal(kek, bytes.fromhex(header["wrapped"]), b"awv-dk")
    except CorruptRecord as e:
        raise WrongPassphrase("wrong passphrase or damaged vault header") from e


def rewrap_key(dk: bytes, new_passphrase: str, kdf: dict | None = None) -> dict:
    kdf = kdf or DEFAULT_KDF
    salt = os.urandom(16)
    wrapped = seal(derive_kek(new_passphrase, salt, kdf), dk, b"awv-dk")
    return {"salt": salt.hex(), "kdf": kdf, "wrapped": wrapped.hex()}


def mac_key(dk: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, None, b"awv-mac").derive(dk)


def mac(dk: bytes, data: bytes) -> str:
    return hmac.new(mac_key(dk), data, hashlib.sha256).hexdigest()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
