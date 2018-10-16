from src.classFrames import NetworkLAN
import pyshark
from pyshark import *

folder:str='/home/edoardo/MEGAsync/Tesi/pcap/'
files:list=['ArsenaleCapture_filtered.pcapng',
            'casaCapture_filtered.pcapng',
            'catturaArsenale_filtered.pcapng',
            'golf_filtered.pcapng',
            'mdns_responses_filtered.pcap',
            'unipi-multicast_fitered.pcap'
            ]
net=NetworkLAN()
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