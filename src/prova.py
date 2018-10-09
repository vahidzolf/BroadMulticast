import pyshark
from pyshark import *
from pyshark.capture.capture import *
from pyshark.capture.file_capture import *
from pyshark.capture import *
from pyshark.packet.layer import *
from pyshark.packet.packet import *
from pyshark.tshark.tshark import *

print('tshark config:',get_config())

cap = pyshark.FileCapture("/home/edoardo/MEGAsync/Tesi/test_canon.pcap")

folder:str='/home/edoardo/MEGAsync/Tesi/'
files:list=['unipi-multicast.pcap_test.pcap',   #0
            'unipi-multicast.pcap.gz',
            'unipi-multicast_fitered.pcap',     #2
            'ArsenaleCapture_filtered.pcapng',
            'casaCapture_filtered.pcapng',      #4
            'casaCapture_filtered_missed.pcapng'
            ]
num_pkt_contain:list=[5,
                      35516,
                      516,
                      31,
                      68,
                      47
]
for i in range(len(files)):
    cap:FileCapture=pyshark.FileCapture(
        input_file=folder+files[i],
        keep_packets=False
    )
    cap.load_packets(0)
    print('#',i ,cap, '\tlen(cap)=', len(cap))

    cnt:int=0
    for k in cap:
        cnt+=1
        if(cnt==len(cap)):
            k:Packet=k
            print('#', i, 'last pkt read:', k.sniff_time)
    print('#',i,'\t',files[i],'\tletti --->',cnt,'/',num_pkt_contain[i])
    #pkt:Packet=cap[cnt-1]
    #pkt.show
    cap.close()
    cap.clear()