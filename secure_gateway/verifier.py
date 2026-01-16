from pathlib import Path
from datetime import datetime, timezone
import json
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

BASE_DIR = Path(__file__).resolve().parents[1]
KEYS_DIR = BASE_DIR / "keys"

MAX_DRIFT_SECONDS = 60  # desarrollo

def load_public_key_for_node(node_id: str) -> Ed25519PublicKey:
    key_path = KEYS_DIR / f"{node_id}_public.pem"

    if not key_path.exists():
        available = [p.name for p in KEYS_DIR.glob("*_public.pem")]
        raise FileNotFoundError(
            f"Clave pública no encontrada para nodo '{node_id}'. "
            f"Disponibles: {available}"
        )

    with open(key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def validate_timestamp(timestamp_str: str):
    event_time = datetime.fromisoformat(timestamp_str)

    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    delta = abs((now - event_time).total_seconds())

    if delta > MAX_DRIFT_SECONDS:
        raise ValueError("Evento fuera de ventana temporal")

def verify_event_signature(event: dict) -> bool:
    if "node_id" not in event:
        raise ValueError("Evento sin node_id")

    if "signature" not in event:
        raise ValueError("Evento sin firma")

    public_key = load_public_key_for_node(event["node_id"])

    event_copy = event.copy()
    signature = base64.b64decode(event_copy.pop("signature"))

    message = json.dumps(event_copy, sort_keys=True).encode("utf-8")

    public_key.verify(signature, message)

    return True
