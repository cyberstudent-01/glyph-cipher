"""Authenticated credential encryption using a custom glyph alphabet."""

from __future__ import annotations

import base64
import binascii
import os
import string

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class GlyphCipherError(Exception):
    """Raised when glyph data cannot be safely decoded or decrypted."""


GLYPH_ALPHABET = [
    "§", "¶", "∆", "Ω", "≈", "≠", "⌘", "⌖",
    "✦", "❖", "◈", "⬡", "⬢", "⟁", "⧖", "⧗",
    "⊕", "⊗", "⊙", "⊚", "⋆", "⋇", "⋈", "⋉",
    "⋊", "⋋", "⋌", "⌂", "⌐", "¬", "⌠", "⌡",
    "⌇", "⌈", "⌉", "⌊", "⌋", "⌤", "⌥", "⌦",
    "⌧", "⌨", "⌫", "⌬", "⌭", "⌮", "⌯", "⌰",
    "⌱", "⌲", "⌳", "⌴", "⌵", "⌶", "⌷", "⌸",
    "⌹", "⌺", "⌻", "⌼", "⌽", "⌾", "⌿", "⍀",
]
assert len(GLYPH_ALPHABET) == 64
assert len(set(GLYPH_ALPHABET)) == 64
assert all(not glyph.isspace() for glyph in GLYPH_ALPHABET)

_BASE64_ALPHABET = string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
_GLYPH_TO_BASE64 = dict(zip(GLYPH_ALPHABET, _BASE64_ALPHABET))
_BASE64_TO_GLYPH = dict(zip(_BASE64_ALPHABET, GLYPH_ALPHABET))
_SALT_LENGTH = 16
_NONCE_LENGTH = 12
_KEY_LENGTH = 32
_PBKDF2_ITERATIONS = 600_000


def bytes_to_glyphs(data: bytes) -> str:
    """Encode bytes as unpadded URL-safe Base64 represented by custom glyphs."""
    encoded = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    return "".join(_BASE64_TO_GLYPH[character] for character in encoded)


def glyphs_to_bytes(glyphs: str) -> bytes:
    """Decode a custom glyph string into its original bytes."""
    if not isinstance(glyphs, str) or any(character not in _GLYPH_TO_BASE64 for character in glyphs):
        raise GlyphCipherError("The input contains symbols outside the glyph alphabet.")

    encoded = "".join(_GLYPH_TO_BASE64[character] for character in glyphs)
    encoded += "=" * (-len(encoded) % 4)
    try:
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
        canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
        if encoded.rstrip("=") != canonical:
            raise GlyphCipherError("The glyph string is not canonical encoded data.")
        return decoded
    except (binascii.Error, ValueError) as exc:
        raise GlyphCipherError("The glyph string is not valid encoded data.") from exc


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    if not isinstance(passphrase, str) or not passphrase:
        raise GlyphCipherError("The passphrase must not be empty.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt_credential(credential: str, passphrase: str) -> str:
    """Encrypt a credential and return its authenticated glyph representation."""
    if not isinstance(credential, str):
        raise GlyphCipherError("The credential must be text.")
    salt = os.urandom(_SALT_LENGTH)
    nonce = os.urandom(_NONCE_LENGTH)
    ciphertext = AESGCM(_derive_key(passphrase, salt)).encrypt(
        nonce, credential.encode("utf-8"), None
    )
    return bytes_to_glyphs(salt + nonce + ciphertext)


def decrypt_credential(glyphs: str, passphrase: str) -> str:
    """Authenticate and decrypt a glyph representation into the original text."""
    try:
        payload = glyphs_to_bytes(glyphs)
        minimum_length = _SALT_LENGTH + _NONCE_LENGTH + 16
        if len(payload) < minimum_length:
            raise GlyphCipherError("The glyph string is too short to contain a credential.")
        salt = payload[:_SALT_LENGTH]
        nonce = payload[_SALT_LENGTH:_SALT_LENGTH + _NONCE_LENGTH]
        ciphertext = payload[_SALT_LENGTH + _NONCE_LENGTH:]
        plaintext = AESGCM(_derive_key(passphrase, salt)).decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except GlyphCipherError:
        raise
    except (InvalidTag, UnicodeDecodeError, ValueError, TypeError) as exc:
        raise GlyphCipherError("Decryption failed: wrong passphrase or altered glyphs.") from exc
