from pathlib import Path
from datetime import datetime, timezone
import json
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# Directorio base del proyecto
BASE_DIR = Path(__file__).resolve().parents[1]

# Carpeta donde viven las claves públicas (local, NO versionada)
KEYS_DIR = BASE_DIR / "keys"

# Ventana temporal permitida (en segundos)
MAX_DRIFT_SECONDS = 60  # modo desarrollo

def load_public_key_for_node(node_id: str) -> Ed25519PublicKey:
    """
    Carga la clave pública asociada a un node_id específico.
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

def validate_timestamp(timestamp_str: str):
    """
    Valida que el evento esté dentro de la ventana temporal permitida.
    Protege contra replay attacks.
    """
    event_time = datetime.fromisoformat(timestamp_str)

    # Asegurar que el timestamp esté en UTC
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)

    delta = abs((now - event_time).total_seconds())

    if delta > MAX_DRIFT_SECONDS:
        raise ValueError("Evento fuera de ventana temporal")

def verify_event_signature(event: dict) -> bool:
    """
    Verifica:
    - Presencia de node_id
    - Presencia de firma
    - Ventana temporal
    - Firma criptográfica válida
    """

    if "node_id" not in event:
        raise ValueError("Evento sin node_id")

    if "signature" not in event:
        raise ValueError("Evento sin firma")

    if "timestamp" not in event:
        raise ValueError("Evento sin timestamp")

    # Validación temporal (anti-replay)
    validate_timestamp(event["timestamp"])

    # Extraer firma y reconstruir mensaje
    signature_b64 = event.pop("signature")
    signature = base64.b64decode(signature_b64)

    public_key = load_public_key_for_node(event["node_id"])

    # Serialización determinística del evento (CRÍTICO)
    message = json.dumps(event, sort_keys=True).encode("utf-8")

    # Verificación criptográfica
    public_key.verify(signature, message)

    return True
