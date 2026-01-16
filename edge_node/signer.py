import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

def load_private_key(path) -> Ed25519PrivateKey:
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )

def sign_event(event: dict, private_key: Ed25519PrivateKey) -> str:
    event_bytes = json.dumps(event, sort_keys=True).encode("utf-8")
    signature = private_key.sign(event_bytes)
    return base64.b64encode(signature).decode("utf-8")
