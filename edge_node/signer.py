import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def load_private_key(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )

def sign_event(event: dict, private_key: Ed25519PrivateKey) -> str:
    event_bytes = json.dumps(event, sort_keys=True).encode()
    signature = private_key.sign(event_bytes)
    return signature.hex()
