import json
from pathlib import Path

from secure_gateway.verifier import verify_event_signature
from secure_gateway.replay_cache import is_replayed, mark_as_seen
from secure_gateway.validation import is_timestamp_valid

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
            # Validación temporal
            if not is_timestamp_valid(event["timestamp"]):
                raise ValueError("Evento fuera de ventana temporal")

            #  Replay persistente
            if is_replayed(event):
                raise ValueError("Replay detectado (evento ya procesado)")

            # Firma criptográfica
            verify_event_signature(event.copy())

            #  Marcar como visto SOLO si todo fue válido
            mark_as_seen(event)

            print(f"[✓] Evento válido: {event_file.name}")

        except Exception as e:
            print(f"[✗] Evento rechazado: {event_file.name} → {e}")


if __name__ == "__main__":
    process_events()
