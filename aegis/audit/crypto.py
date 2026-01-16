import json
import hashlib
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey
)
from cryptography.exceptions import InvalidSignature


def canonical_json(data: dict) -> str:
    """
    JSON canónico: mismo contenido → mismo hash
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_hash(entry: dict) -> str:
    """
    Calcula hash SHA256 del contenido relevante
    (sin incluir hash ni firma)
    """
    material = {
        k: entry[k]
        for k in entry
        if k not in ("hash", "signature")
    }
    return hashlib.sha256(
        canonical_json(material).encode("utf-8")
    ).hexdigest()


def sign_hash(private_key_path: str, digest: str) -> str:
    """
    Firma el hash usando Ed25519 (sin padding, sin hash externo)
    """
    with open(private_key_path, "rb") as f:
        private_key: Ed25519PrivateKey = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    signature = private_key.sign(digest.encode("utf-8"))

    return base64.b64encode(signature).decode("utf-8")


def verify_signature(public_key_path: str, digest: str, signature_b64: str) -> bool:
    """
    Verifica firma Ed25519 del hash
    """
    with open(public_key_path, "rb") as f:
        public_key: Ed25519PublicKey = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            digest.encode("utf-8")
        )
        return True
    except InvalidSignature:
        return False
