import json
from pathlib import Path
from secure_gateway.verifier import verify_event_signature

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
            verify_event_signature(event.copy())
            print(f"[✓] Evento válido: {event_file.name}")

        except Exception as e:
            print(f"[✗] Evento rechazado: {event_file.name} → {e}")

if __name__ == "__main__":
    process_events()
