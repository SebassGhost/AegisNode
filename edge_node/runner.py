import os
import time
import json
from datetime import datetime
from pathlib import Path

def run_edge_node():
    node_id = os.getenv("NODE_ID", "unknown-node")
    out_dir = os.getenv("DATA_OUT", "data/outgoing")

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    print(f"[*] Edge node activo: {node_id}")
    print(f"[*] Output dir: {out_path.resolve()}")
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

            filename = out_path / f"event_{counter}.json"
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(event, f, indent=2)

            print(f"[+] Evento generado: {filename.name}")
            time.sleep(3)

    except KeyboardInterrupt:
        print("\n[!] Edge node detenido limpiamente")
