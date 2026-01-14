import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_symmetric_key() -> bytes:
    """
    Genera una clave simétrica de 256 bits (32 bytes).
    Esta clave NO debe almacenarse en claro.
    """
    return os.urandom(32)


def encrypt_payload(
    plaintext: bytes,
    key: bytes,
    associated_data: bytes = None
) -> dict:
    """
    Cifra un payload usando AES-256-GCM.

    plaintext: datos a cifrar
    key: clave simétrica (32 bytes)
    associated_data: datos autenticados pero no cifrados (AAD)
    """
    aesgcm = AESGCM(key)

    # Nonce de 96 bits (recomendado para GCM)
    nonce = os.urandom(12)

    # Cifra y autentica el payload
    ciphertext = aesgcm.encrypt(
        nonce=nonce,
        data=plaintext,
        associated_data=associated_data
    )

    return {
        "nonce": nonce,
        "ciphertext": ciphertext,
        "aad": associated_data
    }


def decrypt_payload(
    encrypted_data: dict,
    key: bytes
) -> bytes:
    """
    Descifra un payload AES-GCM.
    Si el ciphertext o AAD fueron alterados, lanza excepción.
    """
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(
        nonce=encrypted_data["nonce"],
        data=encrypted_data["ciphertext"],
        associated_data=encrypted_data["aad"]
    )

