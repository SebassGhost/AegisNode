from pathlib import Path
import time
import hashlib

BASE_DIR = Path(__file__).resolve().parents[1]
CACHE_DIR = BASE_DIR / "data" / "replay_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

WINDOW_SECONDS = 60  # ventana temporal

def _fingerprint(event: dict) -> str:
    """
    Huella mínima e irreversible del evento.
    """
    material = f"{event['node_id']}|{event['event_id']}|{event['timestamp']}"
    return hashlib.sha256(material.encode()).hexdigest()

def is_replayed(event: dict) -> bool:
    """
    Verifica replay persistente.
    """
    fp = _fingerprint(event)
    marker = CACHE_DIR / fp
    return marker.exists()

def mark_as_seen(event: dict):
    """
    Marca evento como procesado (persistente).
    """
    fp = _fingerprint(event)
    marker = CACHE_DIR / fp
    marker.write_text(str(time.time()))
