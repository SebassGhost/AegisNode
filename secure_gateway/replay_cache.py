import time

NONCE_CACHE = {}
WINDOW_SECONDS = 60  # ventana temporal permitida


def is_timestamp_valid(event_timestamp: float) -> bool:
    """
    Verifica que el evento esté dentro de la ventana de tiempo.
    """
    now = time.time()
    return abs(now - event_timestamp) <= WINDOW_SECONDS


def is_nonce_valid(nonce: str, event_timestamp: float) -> bool:
    """
    Verifica que el nonce no haya sido usado antes.
    Limpia nonces antiguos automáticamente.
    """
    now = time.time()

    # limpieza de nonces antiguos
    for n, ts in list(NONCE_CACHE.items()):
        if now - ts > WINDOW_SECONDS:
            del NONCE_CACHE[n]

    if nonce in NONCE_CACHE:
        return False

    NONCE_CACHE[nonce] = event_timestamp
    return True
