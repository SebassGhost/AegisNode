import json
import time
from pathlib import Path
from datetime import datetime, timezone

from secure_gateway.firewall import firewall_check
from secure_gateway.verifier import verify_event_signature, validate_timestamp
from secure_gateway.replay_cache import is_replayed, mark_as_seen
from aegis.audit.logger import append_audit_event

BASE_DIR = Path(__file__).resolve().parents[1]
EVENTS_DIR = BASE_DIR / "data" / "outgoing"
PROCESSED_DIR = BASE_DIR / "data" / "processed"

PRIVATE_KEY_PATH = "keys/local-node_private.pem"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)


def process_event_file(event_file: Path):
    with open(event_file, "r", encoding="utf-8") as f:
        event = json.load(f)

    decision = "REJECTED"
    reason = "Unknown"

    try:
        # 1. Firewall
        firewall_check(event)

        # 2. Timestamp
        validate_timestamp(event["timestamp"])

        # 3. Replay
        if is_replayed(event):
            raise ValueError("REPLAY")

        # 4. Firma
        verify_event_signature(event)

        mark_as_seen(event)

        decision = "ACCEPTED"
        reason = "OK"

        print(f"[✓] Evento aceptado: {event_file.name}")

    except Exception as e:
        reason = str(e)
        print(f"[✗] Evento rechazado: {event_file.name} → {reason}")

    finally:
        append_audit_event(
            audit_type="EVENT_PROCESSING",
            data={
                "event_id": event.get("event_id"),
                "node_id": event.get("node_id"),
                "decision": decision,
                "reason": reason,
                "file": event_file.name,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            private_key_path=PRIVATE_KEY_PATH
        )

        # mover evento ya procesado
        event_file.rename(PROCESSED_DIR / event_file.name)


def run_gateway():
    print("[*] Secure Gateway activo")
    print("[*] Esperando eventos...\n")

    while True:
        events = sorted(EVENTS_DIR.glob("event_*.json"))

        if not events:
            time.sleep(1)
            continue

        for event_file in events:
            process_event_file(event_file)
