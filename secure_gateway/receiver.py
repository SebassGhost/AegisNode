import json
import time
from pathlib import Path
from datetime import datetime, timezone

from secure_gateway.firewall import apply_firewall_rules, FirewallViolation
from secure_gateway.verifier import verify_event_signature, validate_timestamp
from secure_gateway.replay_cache import is_replayed, mark_as_seen
from secure_gateway.threats import ThreatLevel
from aegis.audit.logger import append_audit_event

BASE_DIR = Path(__file__).resolve().parents[1]
EVENTS_DIR = BASE_DIR / "data" / "outgoing"
PROCESSED_DIR = BASE_DIR / "data" / "processed"

PRIVATE_KEY_PATH = "keys/local-node_private.pem"


def classify_threat(exc: Exception) -> ThreatLevel:
    if isinstance(exc, FirewallViolation):
        return ThreatLevel.POLICY
    if "Replay" in str(exc):
        return ThreatLevel.REPLAY
    if "signature" in str(exc).lower():
        return ThreatLevel.INVALID_SIG
    return ThreatLevel.EVIL


def process_event_file(event_file: Path):
    with open(event_file, "r", encoding="utf-8") as f:
        event = json.load(f)

    decision = "REJECTED"
    threat = ThreatLevel.EVIL
    reason = "Unknown"

    try:
        apply_firewall_rules(event)
        validate_timestamp(event["timestamp"])

        if is_replayed(event):
            raise ValueError("Replay detectado")

        verify_event_signature(event)
        mark_as_seen(event)

        decision = "ACCEPTED"
        threat = ThreatLevel.OK
        reason = "Evento válido"

        print(f"[✓] {event_file.name} → OK")

    except Exception as e:
        threat = classify_threat(e)
        reason = str(e)
        print(f"[✗] {event_file.name} → {threat.value}")

    finally:
        append_audit_event(
            audit_type="EVENT_PROCESSING",
            data={
                "event_id": event.get("event_id"),
                "node_id": event.get("node_id"),
                "decision": decision,
                "threat": threat.value,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat()
            },
            private_key_path=PRIVATE_KEY_PATH
        )

        PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
        event_file.rename(PROCESSED_DIR / event_file.name)


def run_gateway():
    print("[*] Secure Gateway activo")
    print("[*] Esperando eventos...")

    while True:
        for event_file in sorted(EVENTS_DIR.glob("event_*.json")):
            process_event_file(event_file)

        time.sleep(2)


if __name__ == "__main__":
    run_gateway()
