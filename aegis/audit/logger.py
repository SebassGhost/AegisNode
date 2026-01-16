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


def append_audit_event(
    event: str,
    node_id: str,
    details: dict,
    private_key_path: str
):
    entry = {
        "timestamp": time.time(),
        "event": event,
        "node_id": node_id,
        "details": details,
        "prev_hash": _get_last_hash()
    }

    entry["hash"] = compute_hash(entry)
    entry["signature"] = sign_hash(private_key_path, entry["hash"])

    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
