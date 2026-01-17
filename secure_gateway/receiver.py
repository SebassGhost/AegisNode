import json
from pathlib import Path
from datetime import datetime, timezone

from secure_gateway.firewall import (
    firewall_check,
    FirewallViolation
)

from secure_gateway.verifier import (
    verify_event_signature,
    validate_timestamp
)

from secure_gateway.replay_cache import (
    is_replayed,
    mark_as_seen
)

from aegis.audit.logger import append_audit_event

# ======================
# CONFIGURACIÓN
# ======================

BASE_DIR = Path(__file__).resolve().parents[1]
EVENTS_DIR = BASE_DIR / "data" / "outgoing"

NODE_ID = "local-node"
PRIVATE_KEY_PATH = "keys/local-node_private.pem"

# ======================
# RECEIVER PRINCIPAL
# ======================

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
            # 1. Firewall lógico (fail fast)
            firewall_check(event)

            # 2. Validación temporal
            validate_timestamp(event["timestamp"])

            # 3. Protección replay
            if is_replayed(event):
                raise ValueError("Replay detectado")

            # 4. Verificación criptográfica
            verify_event_signature(event)

            # 5. Marcar como procesado
            mark_as_seen(event)

            decision = "ACCEPTED"
            reason = "Evento válido"

            print(f"[✓] Evento válido: {event_file.name}")

        except FirewallViolation as fw:
            reason = f"{fw.code} - {str(fw)}"
            print(
                f"[✗] Evento bloqueado por firewall: "
                f"{event_file.name} → {reason} (severity={fw.severity})"
            )

        except Exception as e:
            reason = str(e)
            print(f"[✗] Evento rechazado: {event_file.name} → {reason}")

        finally:
            # Auditoría SIEM-style (siempre se ejecuta)
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

# ======================
# ENTRYPOINT
# ======================

if __name__ == "__main__":
    process_events()
