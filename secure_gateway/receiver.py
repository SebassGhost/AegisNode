import json
from pathlib import Path
from secure_gateway.verifier import load_public_key, verify_event_signature


TRUST_STORE = Path("secure_gateway/trust_store")
INCOMING = Path("data/outgoing")


def process_events():
    public_key_path = TRUST_STORE / "local-node_public.pem"
    public_key = load_public_key(public_key_path)

    for event_file in INCOMING.glob("*.json"):
        with open(event_file, "r", encoding="utf-8") as f:
            event = json.load(f)

        valid = verify_event_signature(event.copy(), public_key)

        if valid:
            print(f"[✓] Evento válido: {event_file.name}")
        else:
            print(f"[✗] Evento ALTERADO: {event_file.name}")


if __name__ == "__main__":
    process_events()
