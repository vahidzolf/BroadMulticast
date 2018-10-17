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

cap:FileCapture=pyshark.FileCapture(input_file=folder+files[6], use_json=True)

for pkt in cap:
    d:DBlspDISC=DBlspDISC(pkt)
    print('host_int:', d.host_int,end=',  ')
    print('version:', d.version,end=',  ')
    print('displayname:',d.displayname,end=',  ')
    print('port:',d.port)
    print(d.namespaces)

for file in files:
    print('###################### ',file,' #######################')
    cap:FileCapture=pyshark.FileCapture(
        input_file=folder+file,
        keep_packets=False
    )
    #cap.load_packets(500)
    count_pkt:int=0
    #cap.next_packet()

    for pkt in cap:
        #cap.load_packets(500)
        net.new_knowledge(pkt)
        count_pkt += 1
        print('.',end='')
    print(count_pkt)


net.printAllAlias()

net.all_kind_protocol()

print('End')