"""Compact, backward-compatible per-install signing for Reverse reports."""

from __future__ import annotations

import base64
import hashlib

import keyring
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

SERVICE = "investigator-dfir"
KEY_NAME = "reverse_provenance_private_key"
ED25519_PREFIX = "ed25519-v1:"


def _private_key():
    encoded = keyring.get_password(SERVICE, KEY_NAME)
    if encoded:
        if encoded.startswith(ED25519_PREFIX):
            raw = base64.b64decode(encoded.removeprefix(ED25519_PREFIX), validate=True)
            return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
        # Compatibility with pre-v2 RSA PEM values on keyrings that accepted them.
        return serialization.load_pem_private_key(base64.b64decode(encoded), password=None)

    key = ed25519.Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    payload = ED25519_PREFIX + base64.b64encode(raw).decode()
    keyring.set_password(SERVICE, KEY_NAME, payload)
    return key


def sign_bytes(data: bytes) -> str:
    key = _private_key()
    if isinstance(key, ed25519.Ed25519PrivateKey):
        return "ed25519:" + base64.b64encode(key.sign(data)).decode()
    if isinstance(key, rsa.RSAPrivateKey):
        signature = key.sign(
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return "rsa-pss-sha256:" + base64.b64encode(signature).decode()
    raise TypeError("Unsupported provenance private key type")


def verify_bytes(data: bytes, signature: str, public_key_pem: str | None = None) -> bool:
    try:
        if ":" in signature:
            algorithm, encoded = signature.split(":", 1)
        else:
            # v1 stored raw base64 RSA-PSS signatures without an algorithm prefix.
            algorithm, encoded = "rsa-pss-sha256", signature
        raw = base64.b64decode(encoded, validate=True)
        public = (
            serialization.load_pem_public_key(public_key_pem.encode())
            if public_key_pem
            else _private_key().public_key()
        )
        if algorithm == "ed25519" and isinstance(public, ed25519.Ed25519PublicKey):
            public.verify(raw, data)
        elif algorithm == "rsa-pss-sha256" and isinstance(public, rsa.RSAPublicKey):
            public.verify(
                raw,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        else:
            return False
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False
    except Exception:
        # Verification is a read-only integrity check and must report failure,
        # not make the trace endpoint unavailable when the OS vault is offline.
        return False


def public_key_info() -> dict[str, str]:
    key = _private_key().public_key()
    pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "public_key_pem": pem.decode(),
        "algorithm": "ed25519" if isinstance(key, ed25519.Ed25519PublicKey) else "rsa-pss-sha256",
        "fingerprint_sha256": hashlib.sha256(pem).hexdigest(),
    }
