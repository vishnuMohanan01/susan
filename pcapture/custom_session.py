import csv
from collections import defaultdict

from scapy.sessions import DefaultSession

from pcapture.features.context.packet_direction import PacketDirection
from pcapture.flow import Flow

EXPIRED_UPDATE = 40
MACHINE_LEARNING_API = "http://localhost:8000/predict"
GARBAGE_COLLECT_PACKETS = 100


class CustomSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):

        self.packets_count = 0
        self.clumped_flows_per_label = defaultdict(list)

        self.TEST01_COUNT = 0
        self.TEST02_COUNT = 0

        super(CustomSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        # Sniffer finished all the packets it needed to sniff.
        # It is not a good place for this, we need to somehow define a finish signal for AsyncSniffer

        return super(CustomSession, self).toPacketList()

    def on_packet_received(self, packet):
        packet_direction = PacketDirection(packet=packet, sys_ip=self.sys_ip)
        direction = packet_direction.get_direction()

        flow = Flow(packet, direction, packet_direction)
        flow.add_packet(packet, direction)
        packet_info = flow.get_data()

        # For test01
        if packet_info['src_ip'] == '134.209.159.150':
            if self.TEST01_COUNT > 10:
                # blacklist ip
                pass

        # For test02
        elif packet_info['src_ip'] == '206.189.130.141':
            if self.TEST02_COUNT > 10:
                # blacklist ip
                pass

        else:
            pass


def generate_session_class(sys_ip):
    return type(
        "NewSession",
        (CustomSession,),
        {
            "sys_ip": sys_ip
        },
    )
