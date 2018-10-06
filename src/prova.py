import pyshark
from pyshark.packet.layer import *
from pyshark.packet.packet import *
cap = pyshark.FileCapture("/home/edoardo/MEGAsync/Tesi/test_canon.pcap")
#cap
#print(cap[0])
pkt:Packet=cap[0]

txts:list=pkt.mdns.dns_txt.all_fields
txts_len:list=pkt.mdns.dns_txt_length.all_fields

txts_cp=txts[:]
txts_len_cp=txts_len[:]

txts.reverse()
txts_len.reverse()
#txts_cp.reverse()
#txts_len_cp.reverse()

for i in range(txts.__len__()):
    i_rv=txts.__len__()-i-1
    print(i_rv,'\t',txts[i_rv].showname_value, '|---|', txts_len[i_rv].showname_value)
    print(i, 'cp', '\t', txts_cp[i].showname_value, '|---|', txts_len_cp[i].showname_value)

for i in range(txts_cp.__len__()):
    i_rv = txts_cp.__len__() - i - 1
    print(i_rv,'\t',txts[i_rv].showname_value, '|---|', txts_len[i_rv].showname_value)
    print(i, 'cp', '\t', txts_cp[i].showname_value, '|---|', txts_len_cp[i].showname_value)
    txt:LayerField=txts.pop()
    txt_len:LayerField=txts_len.pop()
    print(i, 'pop', '\t', txt.showname_value, '|---|', int(txt_len.showname_value))

print(txts.__len__(), txts_cp.__len__(), txts_len.__len__(), txts_len_cp.__len__(),sep='\n')