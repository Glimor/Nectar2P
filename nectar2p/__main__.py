import argparse
from nectar2p.nectar_sender import NectarSender
from nectar2p.nectar_receiver import NectarReceiver


def send_command(args):
    sender = NectarSender(
        args.host,
        args.port,
        enable_encryption=not args.no_encryption,
        stun_server=(args.stun_host, args.stun_port) if args.stun_host else None,
    )
    sender.initiate_secure_connection()
    sender.send_file(args.file)
    sender.close_connection()


def receive_command(args):
    receiver = NectarReceiver(
        args.host,
        args.port,
        enable_encryption=not args.no_encryption,
        stun_server=(args.stun_host, args.stun_port) if args.stun_host else None,
    )
    receiver.wait_for_sender()
    receiver.receive_file(args.output, resume=args.resume)
    receiver.close_connection()


def main():
    parser = argparse.ArgumentParser(description="Nectar2P CLI")
    sub = parser.add_subparsers(dest="cmd")

    send_p = sub.add_parser("send", help="Send a file")
    send_p.add_argument("host")
    send_p.add_argument("port", type=int)
    send_p.add_argument("file")
    send_p.add_argument("--no-encryption", action="store_true", help="Disable encryption")
    send_p.add_argument("--stun-host", help="Custom STUN server host")
    send_p.add_argument("--stun-port", type=int, default=19302, help="STUN server port")
    send_p.set_defaults(func=send_command)

    recv_p = sub.add_parser("receive", help="Receive a file")
    recv_p.add_argument("host")
    recv_p.add_argument("port", type=int)
    recv_p.add_argument("output")
    recv_p.add_argument("--no-encryption", action="store_true", help="Disable encryption")
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

