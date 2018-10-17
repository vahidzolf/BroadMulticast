from pyshark.packet.layer import JsonLayer
from pyshark.packet.packet import Packet

class DBlspDISC:
    '''
    Class that represent db-lsp-disc layer into the packet
    '''
    json_key = 'json.key'
    json_array = 'json.array'
    json_value_number = 'json.value.number'
    json_value_string = 'json.value.string'

    def __init__(self, packet:Packet):
        '''
        Create a new istance of DBlspDISC from given Packet:
         It Parse a "json-dict" into the db-lsp-disc layer of the Packet, filling this instance's fields
        :param packet: packet that contain db-lsp-disc info
        '''
        self.host_int=''
        self.displayname=''
        self.namespaces=[]
        self.version='2.0'
        self.port='17500'
        try:
            db_lsp_disc:JsonLayer = packet['db-lsp-disc']
            jobj = db_lsp_disc._all_fields['json']['json.object']['json.member']
            for j in jobj:
                key = j[self.json_key]
                if(key=='host_int'):
                    self.host_int=j[self.json_value_number]
                elif(key=='displayname'):
                    self.displayname = j[self.json_value_string]
                elif (key == 'namespaces'):
                    self.namespaces = j[self.json_array][self.json_value_number]
                elif (key == 'version'):
                    l:list= j[self.json_array][self.json_value_number]
                    self.version=str(l.pop(0))
                    while(len(l)>0):
                        self.version=self.version + '.' + l.pop(0)
                elif (key == 'port'):
                    self.port = j[self.json_value_number]
        except KeyError:
            print('KeyError**************************')
