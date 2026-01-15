import json
import uuid
from datetime import datetime
from pathlib import Path

from edge_node.sign import sign_event

DATA_OUT = Path("data/outgoing")
DATA_OUT.mkdir(parents=True, exist_ok=True)

EVENT_COUNTER = 0


def generate_event(node_id: str) -> dict:
    """
    Genera un evento base con nonce y timestamp.
    El nonce será usado por el Gateway para replay protection.
    """
    global EVENT_COUNTER
    EVENT_COUNTER += 1

    return {
        "node_id": node_id,
        "event_id": EVENT_COUNTER,
        "timestamp": datetime.utcnow().isoformat(),
        "nonce": str(uuid.uuid4()),  # nonce único por evento
        "type": "demo_capture",
        "payload": {
            "message": "simulated edge event",
            "severity": "low"
        }
    }


def write_event(event: dict):
    """
    Firma el evento y lo escribe en disco.
    El evento SIEMPRE se guarda ya firmado.
    """
    signed_event = sign_event(event)

    filename = DATA_OUT / f"event_{signed_event['event_id']}.json"
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(signed_event, f, indent=2)

    print(f"[+] Evento generado y firmado: {filename.name}")

