from cryptography.hazmat.primitives.serialization import load_pem_private_key

def sign_payload(payload: bytes, private_key_path: str) -> bytes:
    # Carga la clave privada del nodo desde disco
    with open(private_key_path, "rb") as f:
        private_key = load_pem_private_key(f.read(), password=None)

    # Firma el payload completo
    signature = private_key.sign(payload)

    return signature

