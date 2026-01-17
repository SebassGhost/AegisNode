import time
from collections import defaultdict

# ======================
# CONFIGURACIÓN
# ======================

ALLOWED_NODES = {"local-node"}
ALLOWED_EVENT_TYPES = {"INFO", "ALERT", "SECURITY"}

MAX_EVENTS_PER_MINUTE = 30
MAX_PAYLOAD_SIZE = 2048  # bytes

# ======================
# EXCEPCIÓN ESPECIALIZADA
# ======================

class FirewallViolation(Exception):
    def __init__(self, code: str, message: str, severity: str = "MEDIUM"):
        self.code = code
        self.severity = severity
        super().__init__(message)

# ======================
# RATE LIMITING
# ======================

_event_counter = defaultdict(list)

def _rate_limited(fingerprint: str) -> bool:
    now = time.time()
    window_start = now - 60

    timestamps = _event_counter[fingerprint]
    timestamps = [t for t in timestamps if t >= window_start]

    _event_counter[fingerprint] = timestamps

    if len(timestamps) >= MAX_EVENTS_PER_MINUTE:
        return True

    _event_counter[fingerprint].append(now)
    return False

# ======================
# FIREWALL PRINCIPAL
# ======================

def firewall_check(event: dict):
    node_id = event.get("node_id")
    event_type = event.get("type")
    payload = event.get("payload", "")

    # 1. Nodo autorizado
    if node_id not in ALLOWED_NODES:
        raise FirewallViolation(
            code="FW-001",
            message="Nodo no autorizado",
            severity="HIGH"
        )

    # 2. Tipo permitido
    if event_type not in ALLOWED_EVENT_TYPES:
        raise FirewallViolation(
            code="FW-002",
            message="Tipo de evento bloqueado",
            severity="MEDIUM"
        )

    # 3. Rate limiting (fingerprint)
    fingerprint = f"{node_id}:{event_type}"
    if _rate_limited(fingerprint):
        raise FirewallViolation(
            code="FW-003",
            message="Rate limit excedido",
            severity="MEDIUM"
        )

    # 4. Tamaño de payload
    if isinstance(payload, str) and len(payload.encode()) > MAX_PAYLOAD_SIZE:
        raise FirewallViolation(
            code="FW-004",
            message="Payload demasiado grande",
            severity="LOW"
        )

    return True
