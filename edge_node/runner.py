import os
import time
import json
from datetime import datetime
from pathlib import Path

from edge_node.signer import load_private_key, sign_event

def run_edge_node():
    BASE_DIR = Path(__file__).resolve().parents[1]

    node_id = os.getenv("NODE_ID", "local-node")
    out_dir = os.getenv("DATA_OUT", "data/outgoing")

    # Ruta absoluta y real a la clave privada
    private_key_file = BASE_DIR / "keys" / f"{node_id}_private.pem"

    if not private_key_file.exists():
        raise FileNotFoundError(f"Clave privada no encontrada: {private_key_file}")

    private_key = load_private_key(private_key_file)

    out_path = BASE_DIR / out_dir
    out_path.mkdir(parents=True, exist_ok=True)

    print(f"[*] Edge node activo: {node_id}")
    print("[*] Firma criptográfica habilitada")
    print("[*] Captura simulada iniciada (Ctrl+C para detener)")

    counter = 0

    try:
        while True:
            counter += 1

            event = {
                "node_id": node_id,
                "event_id": counter,
                "timestamp": datetime.utcnow().isoformat(),
                "type": "demo_capture",
                "payload": {
                    "message": "simulated edge event",
                    "severity": "low"
                }
            }

            signature = sign_event(event, private_key)
            event["signature"] = signature

            filename = out_path / f"event_{counter}.json"
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(event, f, indent=2)

            print(f"[+] Evento firmado: {filename.name}")
            time.sleep(3)

    except KeyboardInterrupt:
        print("\n[!] Edge node detenido limpiamente")
