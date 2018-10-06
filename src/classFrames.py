from pyshark.packet.packet import Packet
from pyshark.packet.fields import *


class Target:
    _name:str
    _ports:set

    def __init__(self, name:str, port:int):
        self._name = name
        self._ports=set()
        if port > 0:
            self._ports.add(port)

    def add_port(self, new_port: int):
        if new_port > 0:
            self._ports.add(new_port)

    def name(self):
        return self._name[:]

    def ports(self):
        return set(self._ports)


class ServiceMDNS:
    _full_name:str
    _service:str
    _protocol:str
    _domain:str
    _targets:dict
    _txts:dict

    def __init__(self, full_name: str, service: str = '', protocol: str = '', domain: str = ''):
        self._full_name = str(full_name)
        self._targets=dict()
        self._txts=dict()
        if (service != '' or protocol != '' or domain != ''):
            self.update_SRV_detail(service, protocol, domain)

    # GETTERS:
    def name(self):
        return self._full_name[:]

    def service(self):
        return self._service[:]

    def protocol(self):
        return self._protocol[:]

    def domain(self):
        return self._domain[:]

    def targets(self):
        return dict(self._targets)#sorted(self._targets, key=lambda trg: trg.name)

    def txts(self):
        return dict(self._txts)

    def update_SRV_detail(self, service: str, protocol: str, domain: str):
        '''
        Update "service"."protocol"."domain" details
        :param service:
        :param protocol:
        :param domain:
        :return:
        '''
        self._service = service
        self._protocol = protocol
        self._domain = domain

    def add_target(self, targ: str, port: int):
        '''
        Add a new aviable port on a existent target or create a new target
        :param targ:
        :param port:
        :return:
        '''
        if (targ in self._targets):
            self._targets[targ].add_port(port)
        else:
            new_targ = Target(targ, port)
            self._targets[targ] = new_targ

    def add_txt(self, txt: str):
        '''
        Add/Update a txt information about a this service
        :param txt:  str of form " 'key'='value' "
        :return: None, and intert txt in a dictionary made of txts key:value
        '''
        eql_pos = txt.find('=')
        key = txt[:eql_pos]
        val = txt[eql_pos + 1:]
        self._txts[key] = val

    def add_txts(self, dict_txts: dict):
        '''
        Allow to add entair of dictionary's txts
        :param dict_txts: dict containing all txts of form <key:val> (NOT  unique str: " key=val "!)
        :return:
        '''
        for txt_k, txt_v in dict_txts:
            self._txts[txt_k] = txt_v


class Device:
    _id:str
    _lastIPv4:str
    _lastIPv6: str
    _services:dict
    _alias:list

    def __init__(self, dev_id:str, ip:str=''):
        self._id = str(dev_id)
        self.update_IPv4(ip)
        self._services=dict()
        self._alias=list()

    def update_IPv4(self, new_ip: str):
        if new_ip != '' and new_ip != None:
            self._lastIPv4 = str(new_ip)

    def update_IPv6(self, new_ip: str):
        if new_ip != '' and new_ip != None:
            self._lastIPv6 = str(new_ip)

    def update_services(self, new_serv: ServiceMDNS):
        '''
        Update an a existent ServiceSRV, refreshing: details info(serv,proto,domain), targets end txts (if exist).
        Otherwise add a nev ServiceSRV
        :param new_serv: ServiceSRV to add/update
        :return:
        '''
        answ_name = new_serv.name()

        if (answ_name not in self._services):
            self._services[answ_name] = new_serv #TODO: verificare che questo assegnamento non causi problemi(potrebbe essere necessario clonare l'oggetto)
        else:
            serv: ServiceMDNS = self._services[answ_name]

            serv.update_SRV_detail(new_serv.service(), new_serv.protocol(), new_serv.domain())

            for trg_v in new_serv.targets().values():
                trg:Target=trg_v
                for p in trg.ports():
                    serv.add_target(trg.name(),p)

            serv.add_txts(new_serv.txts())

    def add_alias(self, new_alias: str):
        self._alias.append(str(new_alias))

    def id(self):
        return self._id[:]

    def last_IP_know(self):
        return self._lastIPv4[:]

    def get_services(self):
        '''
        :return: Copy of dict containing record ServiceSRV: " MAC_addr_key:ServiceSRV "
        '''
        return dict(self._services)

    def alias(self):
        return self._alias[:]


class NetworkLAN:
    _devices:dict

    def __init__(self):
        self._devices=dict()

    def new_knowledge(self, packet: Packet):
        name:str
        if ('eth' in packet):
            name = packet.eth.src.show[:]
        else:
            return

        dev: Device = None
        if (name in self._devices):
            dev = self._devices[name]
        else:
            dev = Device(name)
            self._devices[name] = dev

        if ('ip' in packet):
            dev.update_IPv4(packet.ip.src.show)

        if ('mdns' in packet and int(packet.mdns.dns_resp_name.all_fields.__len__()) > 0):
            resp_names: list = packet.mdns.dns_resp_name.all_fields[:]
            resp_types: list = packet.mdns.dns_resp_type.all_fields[:]
            resp_lens: list = packet.mdns.dns_resp_len.all_fields[:]
            txts: list = packet.mdns.dns_txt.all_fields[:]
            txts.reverse()
            txts_len: list = packet.mdns.dns_txt_length.all_fields[:]
            txts_len.reverse()

            addr_a: list = packet.mdns.dns_a.all_fields[:]
            addr_aaaa: list = packet.mdns.dns_aaaa.all_fields[:]

            srv_servs:list = packet.mdns.dns_srv_service.all_fields[:]
            srv_protos: list = packet.mdns.dns_srv_proto.all_fields[:]
            srv_doms: list = packet.mdns.dns_srv_name.all_fields[:]
            srv_trgs: list = packet.mdns.dns_srv_target.all_fields[:]
            srv_ports: list = packet.mdns.dns_srv_port.all_fields[:]

            srv: ServiceMDNS = None

            for i in range(0, resp_names.__len__()):
                srv = None
                _typ: LayerField = resp_types[i]
                _nam: LayerField

                if (_typ.hex_value == 16):
                    _nam: LayerField = resp_names[i]
                    srv = ServiceMDNS(_nam.showname_value)
                    r_len = int(resp_lens[i].showname_value)
                    while (r_len > 1):
                        _len:int= int(txts_len.pop().showname_value)+1
                        r_len -=  _len
                        txt:str=txts.pop().showname_value
                        srv.add_txt(txt)

                elif (_typ.hex_value == 1):
                    a: LayerField = addr_a.pop()
                    alias: LayerField = resp_names[i]
                    if (a.showname_value == dev.last_IP_know()):
                        dev.add_alias(alias.showname_value)
                    else:
                        for _d in self._devices:
                            d:Device = _d
                            if (a.showname_value == str(d.last_IP_know())):
                                d.add_alias(alias.showname_value)
                elif (_typ.hex_value == 28):
                    aaaa: LayerField = addr_aaaa.pop()
                    alias: LayerField = resp_names[i]
                    if (aaaa.showname_value == dev.last_IP_know()):
                        dev.add_alias(alias.showname_value)
                    else:
                        for _d in self._devices.values():
                            d: Device = _d
                            _aaaa:str = aaaa.showname_value
                            _ip:str = str(d.last_IP_know())
                            #if (aaaa.showname_value == str(d.last_IP_know())):
                            if(_aaaa==_ip):
                                d.add_alias(alias.showname_value)

                if (srv != None and dev != None):
                    dev.update_services(srv)

            #for _serv in srv_servs:
            while(srv_servs.__len__()>0):
                srv=None
                serv:LayerField = srv_servs.pop() #_serv
                proto:LayerField = srv_protos.pop()
                dom:LayerField = srv_doms.pop()
                trg:LayerField = srv_trgs.pop()
                port:LayerField = srv_ports.pop()

                full_nam_srv:str=serv.showname_value + '.' + proto.showname_value + '.' + dom.showname_value

                srv=ServiceMDNS(full_nam_srv,
                                serv.showname_value,
                                proto.showname_value,
                                dom.showname_value)
                srv.add_target(trg.showname_value, int(port.showname_value))

                if (srv != None and dev != None):
                    dev.update_services(srv)


        else:
            return
