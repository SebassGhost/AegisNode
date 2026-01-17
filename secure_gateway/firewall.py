import time
from collections import defaultdict

class FirewallViolation(Exception):
    def __init__(self, code, message, severity="MEDIUM"):
        self.code = code
        self.severity = severity
        super().__init__(f"{code} - {message} (severity={severity})")

ALLOWED_NODES = {"local-node"}

ALLOWED_EVENT_TYPES = {
    "demo_capture",
    "telemetry",
    "heartbeat"
}

MAX_EVENTS_PER_MINUTE = 30
MAX_PAYLOAD_SIZE = 2048

_event_counter = defaultdict(list)

def _rate_limited(node_id: str) -> bool:
    now = time.time()
    window = now - 60
    _event_counter[node_id] = [
        t for t in _event_counter[node_id] if t >= window
    ]
    if len(_event_counter[node_id]) >= MAX_EVENTS_PER_MINUTE:
        return True
    _event_counter[node_id].append(now)
    return False


def apply_firewall_rules(event: dict):
    node_id = event.get("node_id")
    event_type = event.get("type")
    payload = event.get("payload", "")

    if node_id not in ALLOWED_NODES:
        raise FirewallViolation("FW-001", "Nodo no autorizado", "HIGH")

    if event_type not in ALLOWED_EVENT_TYPES:
        raise FirewallViolation("FW-002", "Tipo de evento bloqueado", "MEDIUM")

    if _rate_limited(node_id):
        raise FirewallViolation("FW-003", "Rate limit excedido", "HIGH")

    if isinstance(payload, str) and len(payload.encode()) > MAX_PAYLOAD_SIZE:
        raise FirewallViolation("FW-004", "Payload demasiado grande", "MEDIUM")

    return True
