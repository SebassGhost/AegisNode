import json
from pathlib import Path
from datetime import datetime, timezone

from aegis.audit.crypto import compute_hash, sign_hash

# ===============================
# Rutas base
# ===============================

BASE_DIR = Path(__file__).resolve().parents[2]
AUDIT_DIR = BASE_DIR / "data" / "audit"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

AUDIT_LOG = AUDIT_DIR / "audit.log"
GENESIS_HASH = "GENESIS"


# ===============================
# Utilidades internas
# ===============================

def _get_last_hash() -> str:
    """
    Obtiene el hash del último evento de auditoría.
    Si no existe el log, retorna GENESIS_HASH.
    """
    if not AUDIT_LOG.exists():
        return GENESIS_HASH

    last_line = None
    with open(AUDIT_LOG, "r", encoding="utf-8") as f:
        for last_line in f:
            pass

    if not last_line:
        return GENESIS_HASH

    return json.loads(last_line)["hash"]


# ===============================
# API pública
# ===============================

def append_audit_event(
    audit_type: str,
    data: dict,
    private_key_path: str
):
    """
    Escribe un evento de auditoría con:
    - Hash encadenado
    - Firma criptográfica
    - Timestamp de registro
    """

    entry = {
        "type": audit_type,
        "logged_at": datetime.now(timezone.utc).isoformat(),
        "previous_hash": _get_last_hash(),
        "data": data,
    }

    # Hash del evento
    entry["hash"] = compute_hash(entry)

    # Firma del hash
    entry["signature"] = sign_hash(private_key_path, entry["hash"])

    # Persistencia append-only
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
