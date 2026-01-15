import json
from pathlib import Path

from secure_gateway.verifier import load_public_key, verify_event_signature

DATA_IN = Path("data/outgoing")


def process_events():
    public_key = load_public_key()

    for file in sorted(DATA_IN.glob("event_*.json")):
        with open(file, "r", encoding="utf-8") as f:
            event = json.load(f)

        try:
            verify_event_signature(event.copy(), public_key)
            print(f"[✓] Evento válido: {file.name}")
        except Exception as e:
            print(f"[✗] Evento rechazado: {file.name} → {e}")


if __name__ == "__main__":
    process_events()
