import json
import time
from pathlib import Path
from aegis.audit.crypto import compute_hash, sign_hash

BASE_DIR = Path(__file__).resolve().parents[2]
AUDIT_DIR = BASE_DIR / "data" / "audit"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

AUDIT_LOG = AUDIT_DIR / "audit.log"
GENESIS_HASH = "GENESIS"


def _get_last_hash() -> str:
    if not AUDIT_LOG.exists():
        return GENESIS_HASH

    with open(AUDIT_LOG, "r", encoding="utf-8") as f:
        last_line = None
        for last_line in f:
            pass

    if not last_line:
        return GENESIS_HASH

    return json.loads(last_line)["hash"]


def append_audit_event(audit_type: str, data: dict):
    """
    Escribe un evento de auditoría con hash encadenado + firma.
    """

    # Cargar último hash (si existe)
    last_hash = None
    if AUDIT_LOG.exists():
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            for line in f:
                pass
            if line:
                last_hash = json.loads(line)["hash"]

    entry = {
        "type": audit_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "previous_hash": last_hash,
        "data": data,
    }

    entry["hash"] = compute_hash(entry)
    entry["signature"] = sign_hash(PRIVATE_KEY_PATH, entry["hash"])

    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
