import argparse
from nectar2p.nectar_sender import NectarSender
from nectar2p.nectar_receiver import NectarReceiver


def send_command(args):
    if not (0 < args.port <= 65535):
        print("Error: Port must be between 1 and 65535")
        return
    
    expected_key = None
    if args.verify_key:
        try:
            with open(args.verify_key, 'rb') as f:
                expected_key = f.read()
        except Exception:
            print("Error: Could not read verification key file")
            return
    
    sender = NectarSender(
        args.host,
        args.port,
        enable_encryption=not args.no_encryption,
        expected_receiver_public_key=expected_key,
        stun_server=(args.stun_host, args.stun_port) if args.stun_host else None,
    )
    sender.initiate_secure_connection()
    sender.send_file(args.file)
    sender.close_connection()


def receive_command(args):
    if not (0 < args.port <= 65535):
        print("Error: Port must be between 1 and 65535")
        return
    
    expected_key = None
    if args.verify_key:
        try:
            with open(args.verify_key, 'rb') as f:
                expected_key = f.read()
        except Exception:
            print("Error: Could not read verification key file")
            return
    
    receiver = NectarReceiver(
        args.host,
        args.port,
        enable_encryption=not args.no_encryption,
        expected_sender_public_key=expected_key,
        stun_server=(args.stun_host, args.stun_port) if args.stun_host else None,
    )
    receiver.wait_for_sender()
    receiver.receive_file(args.output, resume=args.resume)
    receiver.close_connection()


def export_key_command(args):
    from nectar2p.encryption.rsa_handler import RSAHandler
    rsa = RSAHandler()
    public_key = rsa.get_public_key()
    try:
        with open(args.output, 'wb') as f:
            f.write(public_key)
        print(f"Public key exported to: {args.output}")
    except Exception:
        print("Error: Could not write public key file")


def main():
    parser = argparse.ArgumentParser(description="Nectar2P CLI")
    sub = parser.add_subparsers(dest="cmd")

    export_p = sub.add_parser("export-key", help="Export public key for verification")
    export_p.add_argument("output", help="Output file path for public key")
    export_p.set_defaults(func=export_key_command)

    send_p = sub.add_parser("send", help="Send a file")
    send_p.add_argument("host")
    send_p.add_argument("port", type=int)
    send_p.add_argument("file")
    send_p.add_argument("--no-encryption", action="store_true", help="Disable encryption")
    send_p.add_argument("--verify-key", help="Path to receiver's public key file for verification")
    send_p.add_argument("--stun-host", help="Custom STUN server host")
    send_p.add_argument("--stun-port", type=int, default=19302, help="STUN server port")
    send_p.set_defaults(func=send_command)

    recv_p = sub.add_parser("receive", help="Receive a file")
    recv_p.add_argument("host")
    recv_p.add_argument("port", type=int)
    recv_p.add_argument("output")
    recv_p.add_argument("--no-encryption", action="store_true", help="Disable encryption")
    recv_p.add_argument("--verify-key", help="Path to sender's public key file for verification")
    recv_p.add_argument("--stun-host", help="Custom STUN server host")
    recv_p.add_argument("--stun-port", type=int, default=19302, help="STUN server port")
    recv_p.add_argument("--resume", action="store_true", help="Resume an incomplete transfer")
    recv_p.set_defaults(func=receive_command)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()

