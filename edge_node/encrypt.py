from utils.crypto_helpers import encrypt_payload

def secure_payload(payload: bytes, session_key: bytes, metadata: dict) -> dict:
    """
    Cifra el payload antes de salir del edge.

    metadata se convierte en AAD:
    - no se cifra
    - pero queda autenticada
    """
    aad = str(metadata).encode()

    encrypted = encrypt_payload(
        plaintext=payload,
        key=session_key,
        associated_data=aad
    )

    return encrypted

