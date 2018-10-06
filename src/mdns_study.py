from src.classFrames import *
import pyshark
cap=pyshark.FileCapture(
    input_file="/home/edoardo/MEGAsync/Tesi/test_canon.pcap",
    display_filter='mdns'
)
net=NetworkLAN()

for pkt in cap:
    net.new_knowledge(pkt)
    print(pkt,'... added')

print('fine ... fineFIneFiNe...FINEEEEEE...fInE...finE...FIENO!...fine...FINE!!!')