from pathlib import Path
import time
import hashlib

BASE_DIR = Path(__file__).resolve().parents[1]
CACHE_DIR = BASE_DIR / "data" / "replay_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

def _fingerprint(event: dict) -> str:
    """
    Huella única e irreversible del evento.
    """
    material = f"{event['node_id']}|{event['event_id']}|{event['timestamp']}"
    return hashlib.sha256(material.encode()).hexdigest()

def is_replayed(event: dict) -> bool:
    """
    Retorna True si el evento ya fue procesado antes.
    """
    fp = _fingerprint(event)
    return (CACHE_DIR / fp).exists()

def mark_as_seen(event: dict):
    """
    Marca el evento como procesado (persistente).
    """
    fp = _fingerprint(event)
    (CACHE_DIR / fp).write_text(str(time.time()))
