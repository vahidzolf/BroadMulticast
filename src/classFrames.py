from pyshark.packet.packet import Packet
from pyshark.packet.packet_summary import PacketSummary


class Target:
    _name=''
    _ports=set()

    def __init__(self,name:str,port:int=-1):
        self._name=name
        if port>0:
            self._ports.add(port)

    def add_port(self,new_port:int):
        if new_port>0:
            self._ports.add(new_port)

    def name(self):
        return self._name[:]
    def ports(self):
        return set(self._ports)

class ServiceMDNS:
    _full_name=''
    _service=''
    _protocol=''
    _domain=''
    _targets={}
    _txts={}

    def __init__(self,full_name:str, service:str='', protocol:str='', domain:str=''):
        self._full_name=full_name
        if(service!='' or protocol!='' or domain!=''):
            self.update_SRV_detail(service,protocol,domain)

    #GETTERS:
    def name(self):
        return self._full_name[:]
    def service(self):
        return self._service[:]
    def protocol(self):
        return self._protocol[:]
    def domain(self):
        return self._domain[:]
    def targets(self):
        return sorted(self._targets,key=lambda trg: trg.name)
    def txts(self):
        return dict(self._txts)

    def update_SRV_detail(self, service:str, protocol:str, domain:str):
        self._service=service
        self._protocol=protocol
        self._domain=domain

    def add_target(self, targ:str, port:int):
        if(targ in self._targets):
            self._targets[targ].add_port(port)
        else:
            new_targ = Target(targ, port)
            self._targets[targ]=new_targ

    def add_txt(self,txt:str):
        eql_pos = txt.find('=')
        key=txt[:eql_pos]
        val=txt[eql_pos+1:]
        self._txts[key]=val

    def add_txts(self, dict_txts:dict):
        for txt_k,txt_v in dict_txts:
            self._txts[txt_k]=txt_v

class Device:
    _id=''
    _lastIP=''
    _services={}

    def __init__(self, dev_id:str, ip:str=''):
        self._id=dev_id
        self.update_ip(ip)

    def update_ip(self, new_ip:str):
        if new_ip!='':
            self._lastIP=new_ip

    def update_services(self, new_serv:ServiceMDNS):
        answ_name=new_serv.name()

        if(answ_name not in self._services):
            self._services[answ_name]=new_serv
        else:
            serv:ServiceMDNS=self._services[answ_name]

            serv.update_SRV_detail(new_serv.service(),new_serv.protocol(),new_serv.domain())

            for trg in new_serv.targets():
                serv.add_target(trg.name, trg.port)

            serv.add_txts(new_serv.txts())

    def id(self):
        return self._id[:]
    def last_IP_know(self):
        return self._lastIP[:]
    def get_services(self):
        return dict(self._services)

class NetworkLAN:
    _devices={}

    def __init__(self):
        pass

    def new_knowledge(self, packet:Packet):
        name=''
        if('eth' in packet):
            name = packet.eth.src.show
        else:
            return

        dev=None
        if(name in self._devices):
            dev=self._devices[name]
        else:
            dev=Device(name)

        if ('ip' in packet):
            dev.update_ip(packet.ip.src.show)

        if('mdns' in packet and int(packet.mdns.dns_count_answers)>0):


            srv=ServiceMDNS(name)

        else:
            return


