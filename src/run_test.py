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
# files:list=['small.pcap']
files:list=['CNR_Big_capture.pcap']
# files:list=['medium.pcap']

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
            #regardless of the protocol of

    del cap




for file in files:
    # collect Dropbox infos
    cap: FileCapture = pyshark.FileCapture(
        input_file=folder + file,
        keep_packets=False,
        use_json=True,
        display_filter="db-lsp-disc"
    )

    for pkt in cap:
        net.extract_DB_infos(pkt)

    del cap

    # collect nbns and llmnr infos
    cap: FileCapture = pyshark.FileCapture(
        input_file=folder + file,
        keep_packets=False,
        # use_json=True,
        display_filter="llmnr or nbns or arp"
    )

    for pkt in cap:
        if 'llmnr' in pkt:
            net.extract_llmnr_infos(pkt)
        elif 'nbns' in pkt:
            net.extract_nbns_infos(pkt)
        elif 'arp' in pkt:
        #Analyze ARP packets to infer connections
            net.extract_ARP_Links(pkt)
# At this moment there are some nodes which no name assigned to them, while we can try to resolve the IP address of
# them using dns or nmlookup
# net.extract_unknown(file)

# show linked devices
net.extract_DB_links()

#print snapshot of the network
net.printAll()
# net.print_browser_inf()



#net.all_kind_protocol()
#net.all_local_alias()

print('End')
