from scapy.sendrecv import AsyncSniffer

from pcapture.custom_session import generate_session_class


def create_sniffer(input_interface):
    assert (input_interface is None)

    custom_session = generate_session_class()

    return AsyncSniffer(
        iface=input_interface,
        filter="ip and (tcp or udp)",
        prn=None,
        session=custom_session,
        store=False,
        count=0
    )


def main():
    input_interface = None

    sniffer = create_sniffer(input_interface)

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
