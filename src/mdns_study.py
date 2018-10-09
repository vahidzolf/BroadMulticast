from src.classFrames import *
import pyshark
from pyshark import *

folder:str='/home/edoardo/MEGAsync/Tesi/'
files:list=['unipi-multicast.pcap_test.pcap',   #0
            'unipi-multicast.pcap.gz',
            'unipi-multicast_fitered.pcap',     #2
            'ArsenaleCapture_filtered.pcapng',
            'casaCapture_filtered.pcapng'       #4
            ]

cap:FileCapture=pyshark.FileCapture(
    input_file=folder+files[2],
    keep_packets=False
)
#cap.load_packets(500)
net=NetworkLAN()
count_pkt:int=0
#cap.next_packet()

for pkt in cap:
    count_pkt+=1
    print('.',end='')
print('#PACCHETTI in cap:', count_pkt)
count_pkt=0

for pkt in cap:
    #cap.load_packets(500)
    net.new_knowledge(pkt)
    count_pkt += 1
    print(count_pkt, '... added')
    if (count_pkt == 10):
        print(count_pkt, '... added')


print('End')