import time
from collections import defaultdict
from typing import Dict, Any


class FirewallViolation(Exception):
    """
    Excepción base para violaciones de políticas del firewall.
    Incluye código y severidad para clasificación de amenazas.
    """
    def __init__(self, code: str, message: str, severity: str = "MEDIUM"):
        self.code = code
        self.severity = severity
        super().__init__(f"{code} - {message} (severity={severity})")


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
    "telemetry",
    "heartbeat",
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

    # limpiar timestamps fuera de ventana
    _event_counter[node_id] = [
        t for t in _event_counter[node_id] if t >= window_start
    ]

    if len(_event_counter[node_id]) >= MAX_EVENTS_PER_MINUTE:
        return True

    _event_counter[node_id].append(now)
    return False


# ======================
# FIREWALL PRINCIPAL
# ======================

def apply_firewall_rules(event: Dict[str, Any]) -> None:
    """
    Aplica políticas Zero Trust sobre el evento.
    Si el evento viola alguna regla → lanza FirewallViolation.
    Si pasa → no retorna nada.
    """

    node_id = event.get("node_id")
    event_type = event.get("type")
    payload = event.get("payload", "")

    # FW-001: Nodo autorizado
    if not node_id:
        raise FirewallViolation(
            "FW-000",
            "Evento sin node_id",
            "HIGH"
        )

    if node_id not in ALLOWED_NODES:
        raise FirewallViolation(
            "FW-001",
            f"Nodo no autorizado: {node_id}",
            "HIGH"
        )

    # FW-002: Tipo de evento permitido
    if not event_type:
        raise FirewallViolation(
            "FW-000",
            "Evento sin tipo",
            "MEDIUM"
        )

    if event_type not in ALLOWED_EVENT_TYPES:
        raise FirewallViolation(
            "FW-002",
            f"Tipo de evento bloqueado: {event_type}",
            "MEDIUM"
        )

    # FW-003: Rate limiting
    if _rate_limited(node_id):
        raise FirewallViolation(
            "FW-003",
            "Rate limit excedido",
            "HIGH"
        )

    # FW-004: Tamaño de payload
    if isinstance(payload, (dict, list)):
        size = len(str(payload).encode("utf-8"))
    elif isinstance(payload, str):
        size = len(payload.encode("utf-8"))
    else:
        size = 0

    if size > MAX_PAYLOAD_SIZE:
        raise FirewallViolation(
            "FW-004",
            f"Payload demasiado grande ({size} bytes)",
            "MEDIUM"
        )

    # Si llega aquí → evento permitido
    return None
