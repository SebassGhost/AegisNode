import json
from pathlib import Path
from aegis.audit.crypto import compute_hash, verify_signature

BASE_DIR = Path(__file__).resolve().parents[2]
AUDIT_LOG = BASE_DIR / "data" / "audit" / "audit.log"
GENESIS_HASH = "GENESIS"


def verify_audit_log(public_key_path: str):
    if not AUDIT_LOG.exists():
        return False, "No existe audit.log"

    prev_hash = GENESIS_HASH
    index = 0

    with open(AUDIT_LOG, "r", encoding="utf-8") as f:
        for line in f:
            index += 1
            entry = json.loads(line)

            if entry["prev_hash"] != prev_hash:
                return False, f"Cadena rota en evento #{index}"

            expected_hash = compute_hash(entry)
            if entry["hash"] != expected_hash:
                return False, f"Hash inválido en evento #{index}"

            if not verify_signature(
                public_key_path,
                entry["hash"],
                entry["signature"]
            ):
                return False, f"Firma inválida en evento #{index}"

            prev_hash = entry["hash"]

    return True, f"Audit log íntegro ({index} eventos)"
