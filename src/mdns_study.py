from src.classFrames import *
import pyshark
cap=pyshark.FileCapture(
    input_file="/home/edoardo/MEGAsync/Tesi/unipi-multicast.pcap_test.pcap",
    display_filter='mdns'
)
net=NetworkLAN()

for pkt in cap:
    net.new_knowledge(pkt)
    print(pkt,'... added')

print('End')