from scapy.sendrecv import AsyncSniffer

from pcapture.custom_session import generate_session_class


def create_sniffer(clf_model, input_interface, sys_ip):
    assert (input_interface is None)

    custom_session = generate_session_class(clf_model, sys_ip)

    return AsyncSniffer(
        iface=input_interface,
        filter="ip and (tcp or udp)",
        prn=None,
        session=custom_session,
        store=False,
        count=0
    )


def main():
    sniffer = create_sniffer(
        clf_model=clf_model,
        input_interface=input_interface,
        sys_ip=sys_ip
    )

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
