import time
from collections import defaultdict

# ======================
# CONFIGURACIÓN DE POLÍTICAS
# ======================

ALLOWED_NODES = {
    "local-node",
}

ALLOWED_EVENT_TYPES = {
    "INFO",
    "ALERT",
    "SECURITY",
}

MAX_EVENTS_PER_MINUTE = 30
MAX_PAYLOAD_SIZE = 2048  # bytes

# ======================
# RATE LIMITING (en memoria)
# ======================

_event_counter = defaultdict(list)

def _rate_limited(node_id: str) -> bool:
    now = time.time()
    window_start = now - 60

    timestamps = _event_counter[node_id]

    # limpiar eventos antiguos
    _event_counter[node_id] = [
        t for t in timestamps if t >= window_start
    ]

    if len(_event_counter[node_id]) >= MAX_EVENTS_PER_MINUTE:
        return True

    _event_counter[node_id].append(now)
    return False

# ======================
# FIREWALL PRINCIPAL
# ======================

def firewall_check(event: dict):
    """
    Aplica políticas de seguridad lógica sobre el evento.
    Lanza excepción si el evento debe ser bloqueado.
    """

    node_id = event.get("node_id")
    event_type = event.get("type")
    payload = event.get("payload", "")

    # 1. Nodo autorizado
    if node_id not in ALLOWED_NODES:
        raise ValueError("Firewall: nodo no autorizado")

    # 2. Tipo de evento permitido
    if event_type not in ALLOWED_EVENT_TYPES:
        raise ValueError("Firewall: tipo de evento bloqueado")

    # 3. Rate limiting
    if _rate_limited(node_id):
        raise ValueError("Firewall: rate limit excedido")

    # 4. Tamaño de payload
    if isinstance(payload, str) and len(payload.encode()) > MAX_PAYLOAD_SIZE:
        raise ValueError("Firewall: payload demasiado grande")

    return True

