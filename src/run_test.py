import pyshark
from pyshark import *
from pyshark.packet.packet import Packet

from classFrames import NetworkLAN
from DropBox_utils import DBlspDISC


def dropboxStudy(pkt:Packet):
    pass

# folder:str='/root/captures/outdir/'
# files:list=['CNR_chunk_00000_20190222172518.pcap',
#             'CNR_chunk_00002_20190225101908.pcap',
#             'CNR_chunk_00004_20190227235120.pcap',
#             'CNR_chunk_00001_20190224014742.pcap',
#             'CNR_chunk_00003_20190226175640.pcap',
#             'CNR_chunk_00005_20190301070739.pcap',
# ]


folder:str='/root/captures/'
# files:list=['cs_general_fixed.pcap']
files:list=['small.pcap']

net=NetworkLAN()

'''
cap:FileCapture=pyshark.FileCapture(input_file=folder+files[6], use_json=True)

for pkt in cap:
    d:DBlspDISC=DBlspDISC(pkt)
    print('host_int:', d._host_int, end=',  ')
    print('version:', d._version, end=',  ')
    print('displayname:', d._displayname, end=',  ')
    print('port:', d._port)
    print(d._namespaces)
'''



for file in files:
    print('###################### ',file,' #######################')
    # collect mDNS infos
    cap:FileCapture=pyshark.FileCapture(
        input_file=folder+file,
        keep_packets=False,
        use_json=False,
        display_filter = "not arp"
    )
    cap.set_debug()
    count_pkt: int = 0
    mdns_pkt: int = 0
    browser_pkt: int = 0
    dhcp_pkt: int = 0
    dropbox_pkt: int = 0
    for pkt in cap:
        if 'eth' in pkt:
            # collect mdns infos
            if 'mdns' in pkt:
                net.extract_mDNS_info(pkt)
                mdns_pkt += 1
            # collect Browser infos
            elif 'browser' in pkt:
                net.extract_Browser_info(pkt)
                browser_pkt += 1
            # collect DHCP infos
            elif 'bootp' in pkt or 'dhcpv6' in pkt:
                net.extract_DHCP_info(pkt)
                dhcp_pkt += 1
            #regardless of the protocol of
        count_pkt += 1

        if (count_pkt % 1000) == 0:
           print(count_pkt)

    del cap
    # collect Dropbox infos
    cap: FileCapture = pyshark.FileCapture(
        input_file=folder + file,
        keep_packets=False,
        use_json=True,
        display_filter="db-lsp-disc"
    )

    for pkt in cap:
        net.extract_DB_infos(pkt)
        dropbox_pkt += 1

# First we need to identify list of IP addresses of identified nodes


# At this moment there are some nodes which no name assigned to them, while we can try to resolve the IP address of
# them using dns or nmlookup
    net.extract_unknown(file)

#print snapshot of the network
net.printAll()
# net.print_browser_inf()

# show linked devices
#net.print_DB()

#net.all_kind_protocol()
#net.all_local_alias()

print('End')
