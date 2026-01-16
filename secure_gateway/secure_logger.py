from pathlib import Path
import json
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

BASE_DIR = Path(__file__).resolve().parents[1]

LOG_DIR = BASE_DIR / "data" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOG_DIR / "gateway.log"

KEYS_DIR = BASE_DIR / "keys"
GATEWAY_KEY = KEYS_DIR / "gateway_private.pem"


def load_gateway_private_key() -> Ed25519PrivateKey:
    with open(GATEWAY_KEY, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _last_log_hash() -> str:
    """
    Devuelve el hash del último log (o genesis).
    """
    if not LOG_FILE.exists():
        return "GENESIS"

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
        if not lines:
            return "GENESIS"

        last = json.loads(lines[-1])
        return last["entry_hash"]


def write_secure_log(event: dict, status: str):
    """
    Escribe un log firmado y encadenado.
    """
    private_key = load_gateway_private_key()
    prev_hash = _last_log_hash()

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "node_id": event.get("node_id"),
        "event_id": event.get("event_id"),
        "status": status,
        "prev_hash": prev_hash
    }

    serialized = json.dumps(entry, sort_keys=True).encode()
    entry_hash = hashlib.sha256(serialized).hexdigest()
    signature = private_key.sign(serialized).hex()

    entry["entry_hash"] = entry_hash
    entry["signature"] = signature

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
