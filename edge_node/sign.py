import json
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from pathlib import Path

KEY_PATH = Path("keys/local-node/private.key")


def load_private_key() -> Ed25519PrivateKey:
    """
    Carga la clave privada del nodo.
    """
    with open(KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )


def sign_event(event: dict) -> dict:
    """
    Firma el evento completo (excepto el campo 'signature').
    """
    private_key = load_private_key()

    event_copy = event.copy()
    event_bytes = json.dumps(event_copy, sort_keys=True).encode()

    signature = private_key.sign(event_bytes)

    event_copy["signature"] = base64.b64encode(signature).decode()
    return event_copy
