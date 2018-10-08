from src.classFrames import *
import pyshark
from pyshark import *

folder:str='/home/edoardo/MEGAsync/Tesi/'
files:list=['unipi-multicast.pcap_test.pcap','unipi-multicast.pcap.gz']

cap:FileCapture=pyshark.FileCapture(
    input_file=folder+files[1], #
    display_filter='mdns'
)
net=NetworkLAN()
count_pkt:int=0
#cap.next_packet()


for pkt in cap:
    net.new_knowledge(pkt)
    count_pkt += 1
    print(count_pkt, '... added')
    if (count_pkt == 17):
        print(count_pkt, '... added')


print('End')