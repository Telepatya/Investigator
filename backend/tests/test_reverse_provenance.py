from __future__ import annotations

import base64
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.reverse import provenance


class ReverseProvenanceTests(unittest.TestCase):
    def test_ed25519_key_fits_windows_vault_and_verifies(self) -> None:
        vault: dict[tuple[str, str], str] = {}

        def get(service: str, name: str):
            return vault.get((service, name))

        def set_value(service: str, name: str, value: str):
            vault[(service, name)] = value

        with (
            patch.object(provenance.keyring, "get_password", side_effect=get),
            patch.object(provenance.keyring, "set_password", side_effect=set_value),
        ):
            signature = provenance.sign_bytes(b"report")
            payload = vault[(provenance.SERVICE, provenance.KEY_NAME)]
            self.assertLessEqual(len(payload.encode("utf-16-le")), 5 * 512)
            self.assertTrue(payload.startswith(provenance.ED25519_PREFIX))
            self.assertTrue(provenance.verify_bytes(b"report", signature))
            self.assertFalse(provenance.verify_bytes(b"modified", signature))
            info = provenance.public_key_info()
            self.assertEqual(info["algorithm"], "ed25519")

    def test_existing_rsa_key_remains_supported(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        stored = base64.b64encode(pem).decode()
        with patch.object(provenance.keyring, "get_password", return_value=stored):
            signature = provenance.sign_bytes(b"legacy")
            info = provenance.public_key_info()
            self.assertEqual(info["algorithm"], "rsa-pss-sha256")
            self.assertTrue(provenance.verify_bytes(
                b"legacy", signature, info["public_key_pem"]
            ))
            self.assertTrue(provenance.verify_bytes(
                b"legacy", signature.split(":", 1)[1], info["public_key_pem"]
            ))


if __name__ == "__main__":
    unittest.main()
