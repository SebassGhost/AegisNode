import json
from pathlib import Path
from datetime import datetime, timezone

from aegis.firewall import apply_firewall_rules

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
            # 1. Firewall primero (fail fast)
            apply_firewall_rules(event)

            # 2. Validación temporal
            validate_timestamp(event["timestamp"])

            # 3. Replay
            if is_replayed(event):
                raise ValueError("Replay detectado")

            # 4. Firma criptográfica
            verify_event_signature(event)

            # 5. Marcar como visto
            mark_as_seen(event)

            decision = "ACCEPTED"
            reason = "Evento válido"

            print(f"[✓] Evento válido: {event_file.name}")

        except Exception as e:
            reason = str(e)
            print(f"[✗] Evento rechazado: {event_file.name} → {reason}")

        finally:
            # Auditoría obligatoria (SIEM-style)
            append_audit_event(
                audit_type="EVENT_PROCESSING",
                data={
                    "event_id": event.get("event_id"),
                    "node_id": event.get("node_id"),
                    "decision": decision,
                    "reason": reason,
                    "source_file": event_file.name,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                },
                private_key_path=PRIVATE_KEY_PATH
            )


if __name__ == "__main__":
    process_events()
