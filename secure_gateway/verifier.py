from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
import base64

BASE_DIR = Path(__file__).resolve().parents[1]
KEYS_DIR = BASE_DIR / "keys"

def load_public_key_for_node(node_id: str) -> Ed25519PublicKey:
    """
    Carga la clave pública asociada a un node_id.
    """
    key_path = KEYS_DIR / f"{node_id}_public.pem"

    if not key_path.exists():
        available = [p.name for p in KEYS_DIR.glob("*_public.pem")]
        raise FileNotFoundError(
            f"Clave pública no encontrada para nodo '{node_id}'. "
            f"Disponibles: {available}"
        )

    with open(key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def verify_event_signature(event: dict) -> bool:
    """
    Verifica la firma de un evento usando la clave pública del nodo emisor.
    """
    if "signature" not in event:
        raise ValueError("Evento sin firma")

    if "node_id" not in event:
        raise ValueError("Evento sin node_id")

    signature_b64 = event.pop("signature")
    signature = base64.b64decode(signature_b64)

    public_key = load_public_key_for_node(event["node_id"])

    message = str(event).encode("utf-8")

    public_key.verify(signature, message)
    return True
