import pyshark
from pyshark import *
from pyshark.packet.packet import Packet

from classFrames import NetworkLAN
from DropBox_utils import DBlspDISC


def dropboxStudy(pkt:Packet):
    pass



folder:str='/home/edoardo/MEGAsync/Tesi/pcap/'
files:list=['ArsenaleCapture_filtered.pcapng',
            'casaCapture_filtered.pcapng',
            'catturaArsenale_filtered.pcapng',
            'golf_filtered.pcapng',
            'mdns_responses_filtered.pcap',
            'unipi-multicast_fitered.pcap',
            'unipi-multicast_DB.pcap'
            ]
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
        use_json=False
    )
    count_pkt:int=0
    for pkt in cap:
        net.extract_mDNS_info(pkt)
        count_pkt += 1
        print('.',end='')
    print(count_pkt)

    # collect Dropbox infos
    cap: FileCapture = pyshark.FileCapture(
        input_file=folder + file,
        keep_packets=False,
        use_json=True
    )
    count_pkt: int = 0
    for pkt in cap:
        net.extract_DB_infos(pkt)
        count_pkt += 1
        print('.', end='')
    print(count_pkt)

#print snapshot of the network
net.printAll()

# show linked devices
net.print_DB()

#net.all_kind_protocol()
#net.all_local_alias()

print('End')