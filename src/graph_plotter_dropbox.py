import pyshark
from pyshark import *
from pyshark.packet.packet import Packet
import sys
from classFrames import NetworkLAN
from DropBox_utils import DBlspDISC


net=NetworkLAN()


in_file = '/root/captures/medium.pcap'
# in_file = '/root/captures/small.pcap'
# in_file = '/root/captures/outdir/CNR_chunk_00000_20190222172518.pcap'
# in_file = '/root/captures/cs_general_fixed.pcap'

cap: FileCapture = pyshark.FileCapture(
    input_file=in_file,
    keep_packets=False,
    use_json=False,
    display_filter="not arp"
)
# cap.set_debug()

for pkt in cap:
    if 'eth' in pkt:
        # collect mdns infos
        if 'mdns' in pkt:
            net.extract_mDNS_info(pkt)
        # collect Browser infos
        elif 'browser' in pkt:
            net.extract_Browser_info(pkt)
        # collect DHCP infos
        elif 'bootp' in pkt or 'dhcpv6' in pkt:
            net.extract_DHCP_info(pkt)
        # regardless of the protocol of


del cap


cap: FileCapture = pyshark.FileCapture(
    input_file=in_file,
    keep_packets=False,
    use_json=True,
    display_filter="db-lsp-disc"
)

for pkt in cap:
    net.extract_DB_infos_old(pkt)

net.extract_DB_links()


net.print_db_graph(in_file.split('/')[-1])
