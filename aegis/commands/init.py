import os

BASE_DIRS = [
    "keys",
    "logs",
    "data",
    "config"
]

def run(args):
    print("[*] Inicializando AegisNode...")

    for d in BASE_DIRS:
        os.makedirs(d, exist_ok=True)

    print("[+] Estructura base creada")

