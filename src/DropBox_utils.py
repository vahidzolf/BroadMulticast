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

    _host_int : str
    _displayname : str
    _namespaces : set
    _version : str
    _port : str

    def __init__(self, packet:Packet):
        '''
        Create a new istance of DBlspDISC from given Packet:
         It Parse a "json-dict" into the db-lsp-disc layer of the Packet, filling this instance's fields
         NOTE: the packet MUST come from a Filecapture where option 'use_json = True'
        :param packet: packet that contain db-lsp-disc info
        '''
        self._host_int= ''
        self._displayname= ''
        self._namespaces = set()
        self._version= '2.0'
        self._port= '17500'
        try:
            db_lsp_disc:JsonLayer = packet['db-lsp-disc']
            jobj = db_lsp_disc._all_fields['json']['json.object']['json.member']
            for j in jobj:
                key = j[self.json_key]
                if(key=='host_int'):
                    self._host_int=j[self.json_value_number]
                elif(key=='displayname'):
                    self._displayname = j[self.json_value_string]
                elif (key == 'namespaces'):
                    self._namespaces = set(j[self.json_array][self.json_value_number]) #j[self.json_array][self.json_value_number]
                elif (key == 'version'):
                    l:list= j[self.json_array][self.json_value_number]
                    self._version=str(l.pop(0))
                    while(len(l)>0):
                        self._version= self._version + '.' + l.pop(0)
                elif (key == 'port'):
                    self._port = j[self.json_value_number]
        except KeyError:
            print('KeyError**************************')

    def update_ns(self, new_ns:set):
        self._namespaces.update(new_ns)

    def namespaces(self):
        return set(self._namespaces)

    def host_int(self):
        return str(self._host_int)

    def displayname(self):
        return str(self._displayname)

    def version(self):
        return str(self._version)

    def port(self):
        return str(self._port)

    def print(self):
        print('######### Dropbox Infos #########')
        print('host_int:', self._host_int, end=',  ')
        print('version:', self._version, end=',  ')
        print('displayname:', self._displayname, end=',  ')
        print('port:', self._port)
        print(self._namespaces)