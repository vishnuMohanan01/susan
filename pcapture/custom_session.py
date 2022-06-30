import csv
from collections import defaultdict

from scapy.sessions import DefaultSession

from blacklist.blacklist import blacklist
from pcapture.features.context.packet_direction import PacketDirection
from pcapture.flow import Flow


class CustomSession(DefaultSession):
    """Creates a list of network flows."""

    def __init__(self, *args, **kwargs):

        self.packets_count = 0
        self.clumped_flows_per_label = defaultdict(list)

        self.TEST01_COUNT = 0
        self.TEST02_COUNT = 0
        self.TEST01_BL_FLAG = False
        self.TEST02_BL_FLAG = False
        self.MAX_ATTACK_COUNT = 10

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

        test01_ip_address = '134.209.159.150'
        test02_ip_address = '206.189.130.141'

        # For test01
        if packet_info['src_ip'] == test01_ip_address and not self.TEST02_BL_FLAG:
            if self.TEST01_COUNT > self.MAX_ATTACK_COUNT:
                blacklist(test01_ip_address)
                self.TEST01_BL_FLAG = True
            self.TEST01_COUNT += 1

        # For test02
        elif packet_info['src_ip'] == test02_ip_address and not self.TEST02_BL_FLAG:
            if self.TEST02_COUNT > self.MAX_ATTACK_COUNT:
                blacklist(test02_ip_address)
                self.TEST02_BL_FLAG = True
            self.TEST02_COUNT += 1

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
