import pyshark
from pyshark import *
from pyshark.packet.packet import Packet
import sys
from classFrames import NetworkLAN
from DropBox_utils import DBlspDISC




if len(sys.argv) < 4:
    print("invalid usage")
    print("\tUsage: python3 run_test.py <ego_output_path> <printer_file> <Folder_path> <filename_1> <filename_2> ... ")
    print("\tNote that filenames are the name of files resided in Folder_path")
    exit(1)


ego_path = sys.argv[1]
printer_file = sys.argv[2]
folder:str= sys.argv[3]
files = sys.argv[4:]
# folder :str='/root/captures/'

# files:list=['cs_general_fixed.pcap']
# files:list=['CNR_Big_capture.pcap']
# files:list=['medium.pcap']
#files:list=['cs_medium.pcap']
# files:list=['for_debug.pcap']
# files:list=['for_debug_cs.pcap']
# printer_file = 'CS_printer_query_new'

# folder :str='/root/captures/outdir/'
# files:list=['CNR_chunk_00000_20190222172518.pcap',
#             'CNR_chunk_00002_20190225101908.pcap',
#             'CNR_chunk_00004_20190227235120.pcap',
#             'CNR_chunk_00001_20190224014742.pcap',
#             'CNR_chunk_00003_20190226175640.pcap',
#             'CNR_chunk_00005_20190301070739.pcap',
# ]
# files :list = ['CNR_chunk_00005_20190301070739.pcap']



net=NetworkLAN()



net.active_probing()


for file in files:
    print('###################### ',file,' #######################')
    #First we have to allocate slots
    net.form_time_slots(folder+file)
    # collect mDNS infos
    cap:FileCapture=pyshark.FileCapture(
        input_file=folder+file,
        keep_packets=False,
        use_json=False
    )
    # cap.set_debug()

    for pkt in cap:

        # pkt_list.setdefault(file,[])
        #
        # pkt_list[file].append(pkt)

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

    cap.close()




for file in files:
    # collect Dropbox infos
    cap: FileCapture = pyshark.FileCapture(
        input_file=folder + file,
        keep_packets=False,
        use_json=True,
        display_filter="db-lsp-disc"
    )

    for pkt in cap:
        net.extract_DB_infos_old(pkt)

    cap.close()

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
            net.extract_ARP_Links(pkt)

# show linked devices
net.extract_DB_links()

# Online network probing

net.extract_offline_snmp_ip(printer_file)
# net.extract_offline_snmp_mac()
#calculating link weights
net.aggregate_links()

#print snapshot of the network
net.printAll(file)
# net.print_browser_inf()

net.ego_analysis(ego_path)
#net.all_kind_protocol()
#net.all_local_alias()

print('End')
