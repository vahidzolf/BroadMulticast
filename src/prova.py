import pyshark
cap = pyshark.FileCapture("/home/edoardo/MEGAsync/Tesi/test_canon.pcap")
cap
print(cap[0])