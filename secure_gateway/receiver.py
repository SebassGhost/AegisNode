import json
from pathlib import Path
from datetime import datetime, timezone

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

        decision = "REJECTED"
        reason = "Unknown error"

        try:
            # 1. Validación temporal
            validate_timestamp(event["timestamp"])

            # 2. Replay persistente
            if is_replayed(event):
                raise ValueError("Replay detectado")

            # 3. Verificación criptográfica
            verify_event_signature(event)

            # 4. Marcar como procesado
            mark_as_seen(event)

            decision = "ACCEPTED"
            reason = "Evento válido"

            print(f"[✓] Evento válido: {event_file.name}")

        except Exception as e:
            reason = str(e)
            print(f"[✗] Evento rechazado: {event_file.name} → {reason}")

        finally:
            #  Auditoría obligatoria
            append_audit_event(
                audit_type="EVENT_PROCESSING",
                data={
                    "event_id": event.get("event_id"),
                    "node_id": event.get("node_id"),
                    "decision": decision,
                    "reason": reason,
                    "source_file": event_file.name,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )

if __name__ == "__main__":
    process_events()
             
