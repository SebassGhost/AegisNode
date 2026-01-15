import time

NONCE_CACHE = {}
WINDOW_SECONDS = 60

def is_nonce_valid(nonce, timestamp):
    now = time.time()

    # limpiar nonces viejos
    for n, ts in list(NONCE_CACHE.items()):
        if now - ts > WINDOW_SECONDS:
            del NONCE_CACHE[n]

    if nonce in NONCE_CACHE:
        return False

    NONCE_CACHE[nonce] = timestamp
    return True
