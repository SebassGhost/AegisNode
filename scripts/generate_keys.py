from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import os

KEYS_DIR = "keys"
os.makedirs(KEYS_DIR, exist_ok=True)

def generate_node_keys(node_id: str):
    # Genera la clave privada Ed25519
    private_key = Ed25519PrivateKey.generate()

    # Deriva la clave pública desde la privada
    public_key = private_key.public_key()

    # Serializa la clave privada en formato PEM sin cifrar
    # (el cifrado se hará a nivel de filesystem o secret manager)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serializa la clave pública
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Guarda las claves con permisos restrictivos
    with open(f"{KEYS_DIR}/{node_id}_private.pem", "wb") as f:
        f.write(private_bytes)
    os.chmod(f"{KEYS_DIR}/{node_id}_private.pem", 0o600)

    with open(f"{KEYS_DIR}/{node_id}_public.pem", "wb") as f:
        f.write(public_bytes)

    print(f"[+] Identidad criptográfica creada para nodo: {node_id}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Uso: python generate_keys.py <node_id>")
        sys.exit(1)

    generate_node_keys(sys.argv[1])

