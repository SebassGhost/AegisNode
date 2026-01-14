import argparse
from aegis.commands import init, keys, edge, audit

def main():
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AegisNode - Zero Trust Security Architecture CLI"
    )

    subparsers = parser.add_subparsers(dest="command")

    # Comando: init
    init_parser = subparsers.add_parser("init", help="Inicializa el sistema")
    init_parser.set_defaults(func=init.run)

    # Comando: keys
    keys_parser = subparsers.add_parser("keys", help="Gestión de claves")
    keys_sub = keys_parser.add_subparsers(dest="subcommand")

    gen_parser = keys_sub.add_parser("generate", help="Generar claves de nodo")
    gen_parser.add_argument("--node", required=True)
    gen_parser.set_defaults(func=keys.generate)

    # Comando: edge
    edge_parser = subparsers.add_parser("edge", help="Control del edge node")
    edge_sub = edge_parser.add_subparsers(dest="subcommand")

    edge_start = edge_sub.add_parser("start", help="Iniciar edge node")
    edge_start.set_defaults(func=edge.start)

    # Comando: audit
    audit_parser = subparsers.add_parser("audit", help="Auditoría del sistema")
    audit_sub = audit_parser.add_subparsers(dest="subcommand")

    audit_verify = audit_sub.add_parser("verify", help="Verificar integridad")
    audit_verify.set_defaults(func=audit.verify)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

