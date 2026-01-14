import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


def load_public_key(path: str) -> Ed25519PublicKey:
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def verify_event_signature(event: dict, public_key: Ed25519PublicKey) -> bool:
    signature_hex = event.pop("signature", None)

    if not signature_hex:
        raise ValueError("Evento sin firma")

    signature = bytes.fromhex(signature_hex)

    event_bytes = json.dumps(event, sort_keys=True).encode()

    try:
        public_key.verify(signature, event_bytes)
        return True
    except InvalidSignature:
        return False
