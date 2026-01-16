import time

WINDOW_SECONDS = 60  # ventana temporal permitida


def is_timestamp_valid(event_timestamp: float) -> bool:
    """
    Verifica que el evento esté dentro de la ventana temporal permitida.
    Protege contra replay attacks básicos.
    """
    now = time.time()
    return abs(now - event_timestamp) <= WINDOW_SECONDS

