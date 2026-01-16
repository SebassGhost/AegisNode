import json
from pathlib import Path

from secure_gateway.verifier import (
    verify_event_signature,
    validate_timestamp
)
from secure_gateway.replay_cache import (
    is_replayed,
    mark_as_seen
)

from aegis.audit.logger import append_audit_event

BASE_DIR = Path(__file__).resolve().parents[1]
EVENTS_DIR = BASE_DIR / "data" / "outgoing"

NODE_ID = "local-node"
PRIVATE_KEY_PATH = "keys/local-node_private.pem"


def process_events():
    if not EVENTS_DIR.exists():
        print("[!] No hay eventos para procesar")
        return

    for event_file in sorted(EVENTS_DIR.glob("event_*.json")):
        with open(event_file, "r", encoding="utf-8") as f:
            event = json.load(f)

        try:
            # 1. Anti-delay / timestamp
            validate_timestamp(event["timestamp"])

            # 2. Replay persistente
            if is_replayed(event):
                raise ValueError("Replay detectado")

            # 3. Firma criptográfica
            verify_event_signature(event)

            # 4. Marcar como procesado
            mark_as_seen(event)

            # 5. Audit log (aceptado)
            append_audit_event(
                event="EVENT_ACCEPTED",
                node_id=NODE_ID,
                details={
                    "event_id": event.get("event_id"),
                    "source": event_file.name
                },
                private_key_path=PRIVATE_KEY_PATH
            )

            print(f"[✓] Evento válido: {event_file.name}")

        except Exception as e:
            # Audit log (rechazado)
            append_audit_event(
                event="EVENT_REJECTED",
                node_id=NODE_ID,
                details={
                    "event_id": event.get("event_id"),
                    "source": event_file.name,
                    "reason": str(e)
                },
                private_key_path=PRIVATE_KEY_PATH
            )

            print(f"[✗] Evento rechazado: {event_file.name} → {e}")


if __name__ == "__main__":
    process_events()
