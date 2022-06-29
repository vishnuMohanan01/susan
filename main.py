import argparse

from scapy.sendrecv import AsyncSniffer

from pcapture.custom_session import generate_session_class


def create_sniffer(input_interface, sys_ip):
    assert (input_interface is None)

    custom_session = generate_session_class(sys_ip)

    return AsyncSniffer(
        iface=input_interface,
        filter="ip and (tcp or udp)",
        prn=None,
        session=custom_session,
        store=False,
        count=0
    )


def get_commandline_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip',
                        action='store',
                        help='public IPv4 address of the current system',
                        required=True)

    return parser


def main():
    # parse cmd args
    commandline_parser = get_commandline_parser()
    cmd_args = commandline_parser.parse_args()

    """Armour Settings
    """
    input_interface = None
    sys_ip = cmd_args.ip

    sniffer = create_sniffer(input_interface, sys_ip)

    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        sniffer.join()


if __name__ == "__main__":
    """Entry point of susan
    """
    main()
