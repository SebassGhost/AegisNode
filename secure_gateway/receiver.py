import json
from pathlib import Path

from secure_gateway.verifier import verify_event_signature, validate_timestamp
from secure_gateway.replay_cache import is_replayed, mark_as_seen

BASE_DIR = Path(__file__).resolve().parents[1]
EVENTS_DIR = BASE_DIR / "data" / "outgoing"

def process_events():
    if not EVENTS_DIR.exists():
        print("[!] No hay eventos para procesar")
        return

    for event_file in sorted(EVENTS_DIR.glob("event_*.json")):
        with open(event_file, "r", encoding="utf-8") as f:
            event = json.load(f)

        try:
            # 1. Validación temporal (anti-delay / replay)
            validate_timestamp(event["timestamp"])

            # 2. Replay persistente
            if is_replayed(event):
                raise ValueError("Replay detectado")

            # 3. Verificación criptográfica
            verify_event_signature(event)

            # 4. Marcar como procesado
            mark_as_seen(event)

            print(f"[✓] Evento válido: {event_file.name}")

        except Exception as e:
            print(f"[✗] Evento rechazado: {event_file.name} → {e}")

if __name__ == "__main__":
    process_events()
