import json
from pathlib import Path

from secure_gateway.verifier import verify_event_signature
from secure_gateway.validation import is_timestamp_valid
from secure_gateway.replay_cache import is_nonce_valid
from secure_gateway.secure_logger import write_secure_log

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
            # 1️⃣ Verificación criptográfica
            verify_event_signature(event.copy())

            # 2️⃣ Ventana temporal (anti-delay)
            if not is_timestamp_valid(event["timestamp"]):
                raise ValueError("Evento fuera de ventana temporal")

            # 3️⃣ Anti-replay (nonce)
            if not is_nonce_valid(event["nonce"], event["timestamp"]):
                raise ValueError("Replay detectado (nonce reutilizado)")

            # 4️⃣ Evento aceptado
            write_secure_log(event, status="ACCEPTED")
            print(f"[✓] Evento válido: {event_file.name}")

        except Exception as e:
            # Log forense incluso si falla
            write_secure_log(event, status=f"REJECTED: {e}")
            print(f"[✗] Evento rechazado: {event_file.name} → {e}")


if __name__ == "__main__":
    process_events()
