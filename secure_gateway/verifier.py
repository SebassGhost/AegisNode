import json
import base64
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from secure_gateway.replay_cache import is_timestamp_valid, is_nonce_valid


KEY_PATH = Path("keys/local-node/public.key")


def load_public_key() -> Ed25519PublicKey:
    """
    Carga la clave pública del nodo.
    """
    with open(KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def verify_event_signature(event: dict, public_key: Ed25519PublicKey) -> bool:
    """
    Verifica firma, timestamp y replay protection.
    """

    # --- timestamp ---
    if "timestamp" not in event:
        raise ValueError("Evento sin timestamp")

    event_time = datetime.fromisoformat(event["timestamp"]).timestamp()
    if not is_timestamp_valid(event_time):
        raise ValueError("Evento fuera de ventana temporal")

    # --- nonce ---
    if "nonce" not in event:
        raise ValueError("Evento sin nonce")

    if not is_nonce_valid(event["nonce"], event_time):
        raise ValueError("Replay detectado")

    # --- firma ---
    if "signature" not in event:
        raise ValueError("Evento sin firma")

    signature = base64.b64decode(event.pop("signature"))
    event_bytes = json.dumps(event, sort_keys=True).encode()

    public_key.verify(signature, event_bytes)
    return True
