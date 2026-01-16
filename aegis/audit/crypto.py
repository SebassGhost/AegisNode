import json
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def canonical_json(data: dict) -> str:
    """
    JSON canónico: mismo orden → mismo hash
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
    digest = hashlib.sha256(canonical_json(material).encode()).hexdigest()
    return digest


def sign_hash(private_key_path: str, digest: str) -> str:
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    signature = private_key.sign(
        digest.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature.hex()


def verify_signature(public_key_path: str, digest: str, signature_hex: str) -> bool:
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(
            bytes.fromhex(signature_hex),
            digest.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
