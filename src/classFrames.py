from pyshark.packet.packet import Packet
from pyshark.packet.fields import *
from src.discriminators_sets import apple_osx_versions, apple_products, _SPECprot, _ALLprot, keyword_on_alias, common_string, common_string_s
from DropBox_utils import DBlspDISC

# Print or not info of services
DEBUG_SRV = True


class Target:
    ''' Represents a target that is referred to for a service (found in an SRV record), it contain a name and a set of ports'''
    _name: str
    _ports: set

    def __init__(self, name: str, port: int):
        self._name = name
        self._ports = set()
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
    '''Represents a Service record, contain all info, like targets that offer the service and txt additional info'''
    _full_name: str
    _service: str
    _protocol: str
    _domain: str
    _targets: dict
    _txts: dict

    def __init__(self, full_name: str, service: str = '', protocol: str = '', domain: str = ''):
        self._full_name = str(full_name)
        self._targets = dict()
        self._txts = dict()
        self._service = ''
        self._protocol = ''
        self._domain = ''
        self.__dissect_fullname()
        if (service != '' or protocol != '' or domain != ''):
            self.update_SRV_detail(service, protocol, domain)

    def __dissect_fullname(self):
        '''
        It dissect correctly full name of a service, like "instance.service.domain", and acquiring that infos
        :return: None, it acquire separately -> instance, protocol, domain of the service
        '''
        full: list = self._full_name.rsplit('.', 3) # .rsplit(...) -> reverse split => start split from the end of string
        if (len(full) > 3):
            self.update_SRV_detail(full[0], full[1], full[2] + '.' + full[3])
        else:
            # fullname not have all expected fields => starting from the end of split, get all infos aviable
            i: int = len(full) - 1
            dom: str = ''
            proto: str = ''
            istance: str = ''
            if i >= 0:
                dom = full[i]
                i -= 1
            if i >= 0:
                dom = full[i] + '.' + dom # add tcp/udp infos in a domain
                i -= 1
            if i >= 0:
                proto = full[i]
                i -= 1
            if i >= 0:
                istance = full[i]
                i -= 1
            self.update_SRV_detail(istance, proto, dom)

    # GETTERS:
    def name(self):
        return self._full_name[:]

    def service(self):
        cp = self._service[:]
        return cp

    def protocol(self):
        return self._protocol[:]

    def domain(self):
        return self._domain[:]

    def targets(self):
        return dict(self._targets)  # sorted(self._targets, key=lambda trg: trg.name)

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

        if (self._service == '' and service != ''):
            self._service = service
        if (self._protocol == '' and protocol != ''):
            self._protocol = protocol
        if (self._domain == '' and domain != ''):
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
        :return: None, and insert txt in a dictionary made of txts key:value
        '''
        if (txt == None or txt == ''):
            return
        eql_pos: int = txt.find('=')
        if eql_pos > 0:
            key = txt[:eql_pos]
            val = txt[eql_pos + 1:]
            self._txts[key] = val
        else:
            key = str('info-' + str(self._txts.__len__()))
            val = txt[:]
            self._txts[key] = val

    def add_txts(self, dict_txts: dict):
        '''
        Allow to add entair of dictionary's txts
        :param dict_txts: dict containing all txts of form <key:val> (NOT  unique str: " key=val "!)
        :return:
        '''
        for txt_k in dict_txts:
            self._txts[txt_k] = dict_txts[txt_k]


class Device(object):
    '''Represents a Node into the network, and it contain all infos and services that this Node offer '''
    _id: str
    _kind: str      # What kind of device is: Workstation, Printer, ...
    _owner: str
    _lastIPv4: str
    _lastIPv6: str
    _services: dict
    _alias: set     # All names that this device have into this LAN
    _db_lsp_disc: DBlspDISC

    def __init__(self, dev_id: str, ip: str = ''):
        self._id = str(dev_id)
        self._lastIPv4 = ''
        self._lastIPv6 = ''
        self._services = dict()
        self._alias = set()
        self._kind = ''
        self._owner = '???'
        self._db_lsp_disc = None

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
            self._services[answ_name] = new_serv
        else:
            serv: ServiceMDNS = self._services[answ_name]

            serv.update_SRV_detail(new_serv.service(), new_serv.protocol(), new_serv.domain())
            # self.add_alias(new_serv.service())

            for trg_v in new_serv.targets().values():
                trg: Target = trg_v
                for p in trg.ports():
                    serv.add_target(trg.name(), p)

            serv.add_txts(new_serv.txts())

    def remove_service(self, srv: ServiceMDNS):
        '''
        Remove srv from the device services and return it
        :param srv:
        :return:
        '''
        srv_to_rem: str = srv.name()
        if(srv_to_rem in self._services):
            return self._services.pop(srv_to_rem)
        else:
            return None

    def add_alias(self, new_alias: str):
        '''
        Add new alias in a set of aliases of this device. If contain a '@' char, split it and add second part into aliases, \n
        because indicate that this device share a sevice of other device. Also, add first part of alias like "alias.local"
        :param new_alias:
        :return:
        '''
        if (new_alias != None and new_alias != ''):
            self._alias.add(str(new_alias))
            ind_at: int = new_alias.find('@')
            if (ind_at > 0):
                ind_at += 1
                while (new_alias[ind_at] == ' '):
                    ind_at += 1
                new = new_alias[ind_at:]
                self._alias.add(new)
            ind_local: int = new_alias.find('.local')
            if (ind_local > 0):
                new = new_alias[:ind_local]
                self._alias.add((new))

    def update_kind(self):
        '''
        Refresh a kind of device, using 'WhoIsWat' class
        :return:
        '''
        checker: WhoIsWhat = WhoIsWhat(self)
        self._kind = checker.get_kind()
        self._owner = checker.get_owner()

    def update_DB(self, new_db: DBlspDISC):
        '''
        Update Dropbox's infos, like adding new namespaces, announced from this device
        :param new_db:
        :return:
        '''
        if (self._db_lsp_disc == None):
            self._db_lsp_disc = new_db
        else:
            if(new_db.host_int() != self._db_lsp_disc.host_int()):
                print('',end='')
            self._db_lsp_disc.update_ns(new_db.namespaces())

    def get_DB_info(self):
        return self._db_lsp_disc

    def id(self):
        return self._id[:]

    def last_IPv4_know(self):
        return self._lastIPv4[:]

    def last_IPv6_know(self):
        return self._lastIPv6[:]

    def get_services(self):
        '''
        :return: Copy of dict containing record ServiceSRV: " MAC_addr_key:ServiceSRV "
        '''
        return dict(self._services)

    def aliases(self):
        return set(self._alias)

    def kind(self):
        return str(self._kind)

    def owner(self):
        return str(self._owner)


class NetworkLAN:
    '''"Main class", that represents the network under analysis'''
    _devices: dict
    _lost_srv_propertyes: dict
    _namespaces_in_common:dict
    _dropbox_subNET:dict

    def __init__(self):
        self._devices = dict()
        self._lost_srv_propertyes = dict()
        self._namespaces_in_common = dict()
        self._dropbox_subNET = dict()

    def printAll(self):
        ''' Print all infos of the network: devices(MAC addr, aliases, kind, rervices that offer, ...) '''
        for _d in self._devices.values():
            d: Device = _d
            print('***************************************')
            print('Device ID: ', d.id())
            print('Aliases: ', end='')
            for al in d.aliases():
                print(al, end='  || ')
            print('')

            d.update_kind()
            print('How I am: ', d.kind())
            print('Supposed Owner:', d.owner())

            dropbox : DBlspDISC = d.get_DB_info()
            if(dropbox!=None):
                dropbox.print()

            if(DEBUG_SRV):
                for _srv in d.get_services().values():
                    srv: ServiceMDNS = _srv
                    print('\t> ', srv.name())
                    # print('\t   ', srv.service(),'.',srv.protocol(),'.',srv.domain(),sep='')
                    for trg in srv.targets():
                        print('\t   Target', )
                        print('\t          --->', trg)
                    txts: dict = srv.txts()
                    if (txts.__len__() > 0):
                        print('\t   Txts')
                        print('\t   ', end='')
                        for txt_k in txts:
                            print(txt_k, '=', txts[txt_k], sep='', end=' , ')
                        print('')
                print('/----------------------------------/')

    def add_lost_property(self, lost_srv: ServiceMDNS):
        '''
        If a device announce a service that not offer directly, add it into a dict of a lists, with key "target" that offer that service* \n
        * in there is no target, it create a "ficticious target"( not of form "target.local"), use the "istance name" of a service
        :param lost_srv:
        :return:
        '''
        _targets: set = lost_srv.targets()
        if not (len(_targets) > 0):
            _fictitious_trg = lost_srv.service()
            # use where srv record has no targets, and dont knew who provide the service
            _targets[_fictitious_trg] = Target(_fictitious_trg, -1)

            # maybe the target where to refere this service in afret "@" char
            ind_at: int = _fictitious_trg.find('@')
            if (ind_at > 0):
                ind_at += 1
                while (_fictitious_trg[ind_at] == ' '):
                    ind_at += 1
                new = _fictitious_trg[ind_at:]
                _targets[new] = Target(new, -1)

        for trg in _targets:    # here add a record in a dict of "lost services" for every target
            if (trg in self._lost_srv_propertyes):
                _lost_srvs: list = self._lost_srv_propertyes[trg]
                _lost_srvs.append(lost_srv)
            else:
                self._lost_srv_propertyes[trg] = list()
                _lost_srvs: list = self._lost_srv_propertyes[trg]
                _lost_srvs.append(lost_srv)

    def search_lost_propertyes(self, owner: str, device: Device):
        '''
        Giving a device, search if there is a record in a dict of "lost services" with key == "an alias of that device"
        :param owner: first alias of this device to search
        :param device: device that maybe offer a service that other devices has announced
        :return:
        '''
        _owner: str = owner
        dev_to_update: Device = None

        if (_owner in self._lost_srv_propertyes):
            dev_to_update = device
        else:
            _dev_aliases: set = device.aliases()
            for alias in _dev_aliases:
                if (alias in self._lost_srv_propertyes):
                    dev_to_update = device
                    _owner = alias

        if (dev_to_update != None):
            _lost_srvs: list = self._lost_srv_propertyes[_owner]
            while (len(_lost_srvs) > 0):
                _srv: ServiceMDNS = _lost_srvs.pop(0)
                device.update_services(_srv)

    def cleanup(self, device: Device):
        '''
        It remove all services thet this device announce, but it's not sure that this device offer them
        :param device:
        :return:
        '''
        for _srv in device.get_services().values():
            _srv: ServiceMDNS
            _targets = _srv.targets()
            if not (len(_targets) > 0):
                _fictitious_trg = _srv.service()
                # use where srv record has no targets, and dont knew who provide the service
                _targets[_fictitious_trg] = Target(_fictitious_trg, -1)

                # maybe the target where to refer this service is after "@" char
                ind_at: int = _fictitious_trg.find('@')
                if (ind_at > 0):
                    ind_at += 1
                    while (_fictitious_trg[ind_at] == ' '):
                        ind_at += 1
                    new = _fictitious_trg[ind_at:]
                    _targets[new] = Target(new, -1)

            for _trg in _targets:
                if not (_trg in device.aliases()):
                    _lost: ServiceMDNS = device.remove_service(_srv)
                    trg_dev = None
                    for _device in self._devices.values(): # search among all devices if there is one that is a real target
                        _device: Device
                        _aliases: set = _device.aliases()
                        if ((_trg in _aliases)):
                            trg_dev = _device
                            break

                    if(_lost!=None):
                        if (trg_dev != None):
                            trg_dev.update_services(_lost) # there is one that is the real provider of service
                        else:
                            self.add_lost_property(_lost) # no one provide this service

    def extract_mDNS_info(self, packet: Packet):
        '''
        Dissector of a packet: it analyze a packet, searching mDNS's infos, and assign them at a devices discovered inside the network. \n
        It identify devices by MAC addresses, update there IPs(v4/v6)
        :param packet: ONLY form "pyshark.Filecapture" create with option 'use_json=False'
        :return:
        '''
        name: str
        if ('eth' in packet and
                'mdns' in packet and
                # 'dns_count_answers' in packet.mdns and
                packet.mdns.dns_count_answers.hex_value > 0):
            name = packet.eth.src.show[:]
        else:
            return

        try:
            answ_len: int = int(packet.mdns.dns_resp_name.all_fields.__len__())
        except AttributeError:
            return

        dev: Device = None
        if (name in self._devices):
            dev = self._devices[name]
        else:
            dev = Device(name)

        def update(disp: Device, srv_record: ServiceMDNS):
            '''
            Utility function, that update the service record obtained from packet.
            :param disp:
            :param srv_record:
            :return:
            '''
            _dev: Device = None

            for _trgt in srv_record.targets():
                trgt: str = _trgt
                als: set = disp.aliases()
                if (als.__contains__(trgt)):                # device.aliases contains target?
                    disp.add_alias(srv_record.service())        # yes => add alias 'istance' of a service
                    self.search_lost_propertyes(srv_record.service(), disp) # => search inside of 'lost services'
                    _dev = disp
                    break
            if (_dev != None):
                _dev.update_services(srv_record)
            else:
                _dev = disp     # if no one is the provider of this service => assign this service at this device
                for _trgt in srv_record.targets(): # search someone that really offer this service
                    for _d in self._devices.values():
                        d: Device = _d
                        if (d.aliases().__contains__(_trgt)):
                            d.add_alias(srv_record.service())
                            self.search_lost_propertyes(srv_record.service(), d)
                            _dev = d
                            break
                _dev.update_services(srv_record)

        if ('ip' in packet):
            dev.update_IPv4(packet.ip.src.show)

        if ('ipv6' in packet):
            dev.update_IPv6(packet.ipv6.src.show)

        if ('mdns' in packet and answ_len > 0):
            # Create all utility structures, for extract mDNS infos
            resp_names: list = packet.mdns.dns_resp_name.all_fields[:]
            resp_types: list = packet.mdns.dns_resp_type.all_fields[:]
            resp_lens: list = packet.mdns.dns_resp_len.all_fields[:]

            # if there are txt infos into the packet ...
            try:
                txts: list = packet.mdns.dns_txt.all_fields[:]
                txts.reverse()
                txts_len: list = packet.mdns.dns_txt_length.all_fields[:]
                txts_len.reverse()
            except AttributeError:
                txts: list = []
                txts_len: list = []

            # if there are A or AAAA DNS records into the packet ...
            try:
                addr_a: list = packet.mdns.dns_a.all_fields[:]
            except AttributeError:
                addr_a: list = []
            try:
                addr_aaaa: list = packet.mdns.dns_aaaa.all_fields[:]
            except AttributeError:
                addr_aaaa: list = []

            # if there are SRV DNS records into the packet ...
            try:
                srv_servs: list = packet.mdns.dns_srv_service.all_fields[:]
                srv_protos: list = packet.mdns.dns_srv_proto.all_fields[:]
                srv_doms: list = packet.mdns.dns_srv_name.all_fields[:]
                srv_trgs: list = packet.mdns.dns_srv_target.all_fields[:]
                srv_ports: list = packet.mdns.dns_srv_port.all_fields[:]
            except AttributeError:
                srv_servs: list = []
                srv_protos: list = []
                srv_doms: list = []
                srv_trgs: list = []
                srv_ports: list = []

            srv: ServiceMDNS = None

            aaaa_list: list = []    # list of IPv6 addresses
            alias_list: list = []   # list of alias of AAAA records

            while (resp_names.__len__() > 0):

                srv = None
                _typ: LayerField = resp_types.pop(0)  # Type of response record (SRV, TXT, PTR, A, AAAA, ...)
                r_len: int = int(resp_lens.pop(0).showname_value) # len of response record
                _nam: LayerField = None
                if (_typ.hex_value != 33):  # is not present response name if type in SRV(33) => pop from list only if it != SRV
                    _nam: LayerField = resp_names.pop(0)  # resp_names[i]


                ################### DEBUG ################################
                # Trigger debug breakpoints: set condition on 'if', and breakpoint on next line
                if (_nam != None):
                    dbg_str: str = _nam.showname_value
                    if (dbg_str.count('XXXX') > 0 or dev.id() == '08:60:6e:e5:91:a8'):
                        # print('DBG', dbg_str)
                        print('', end='')
                if (_typ.hex_value == 33):
                    # print('DBG', _typ.hex_value)
                    print('', end='')
                #######################################################


                if (_typ.hex_value == 16):  # is a TXT record
                    srv = ServiceMDNS(_nam.showname_value)
                    while (r_len > 0 and (txts.__len__() > 0 and txts_len.__len__() > 0)):
                        # Extract all txts relating this Service's recod
                        _len: int = int(txts_len.pop().showname_value) + 1
                        r_len -= _len
                        txt: str = txts.pop().showname_value
                        if (txt != ''): srv.add_txt(txt)

                elif (_typ.hex_value == 1 and addr_a.__len__() > 0): # is a A record
                    # add/update alias or IPv4 address of the device
                    a: LayerField = addr_a.pop(0)
                    alias: LayerField = _nam  # resp_names[i]
                    if (a.showname_value == dev.last_IPv4_know()): # this device have A.ipv4 address => add alias
                        dev.add_alias(alias.showname_value)
                        self.search_lost_propertyes(alias.showname_value, dev)
                    else:
                        # search a device that have that ipv4 or that alias to update one of them
                        for _d in self._devices.values():
                            d: Device = _d
                            if (a.showname_value == str(d.last_IPv4_know())):
                                d.add_alias(alias.showname_value)
                                self.search_lost_propertyes(alias.showname_value, d)
                            elif (alias.showname_value in d.aliases()):
                                d.update_IPv4(a.showname_value)
                                # self.search_lost_propertyes(alias.showname_value, d)
                elif (_typ.hex_value == 28 and addr_aaaa.__len__() > 0): # is a AAAA record
                    # add address IPv6 and alias into the relative lists
                    aaaa_list.append(addr_aaaa.pop(0))
                    alias_list.append(_nam)

                if (srv != None and dev != None):
                    update(dev, srv)

            # deals with SRV records, that has different management:
            while (srv_servs.__len__() > 0):
                srv = None
                serv: LayerField = srv_servs.pop()
                proto: LayerField = srv_protos.pop()
                dom: LayerField = srv_doms.pop()
                trg: LayerField = srv_trgs.pop()
                port: LayerField = srv_ports.pop()

                # rebuild all infos and package them
                full_nam_srv: str = serv.showname_value + '.' + proto.showname_value + '.' + dom.showname_value

                srv = ServiceMDNS(full_nam_srv,
                                  serv.showname_value,
                                  proto.showname_value,
                                  dom.showname_value)
                srv.add_target(trg.showname_value, int(port.showname_value))

                if (srv != None and dev != None):
                    update(dev, srv)

            while (aaaa_list.__len__() > 0):
                # manage AAAA records, updating aliases or IPv6 of relative device
                aaaa: LayerField = aaaa_list.pop(0)
                alias: LayerField = alias_list.pop(0)  # resp_names[i]
                if (aaaa.showname_value == dev.last_IPv6_know()):
                    dev.add_alias(alias.showname_value)
                    self.search_lost_propertyes(alias.showname_value, dev)
                else:
                    for _d in self._devices.values():
                        d: Device = _d
                        _aaaa: str = aaaa.showname_value
                        _ip: str = str(d.last_IPv6_know())
                        if (_aaaa == _ip):
                            d.add_alias(alias.showname_value)
                            self.search_lost_propertyes(alias.showname_value, d)
                        elif (alias.showname_value in d.aliases()):
                            d.update_IPv6(_aaaa)

        self.cleanup(dev)

        # save the device only if have useful infos
        if (len(dev.aliases()) > 0 or len(dev.get_services()) > 0):
            self._devices[name] = dev

    def extract_DB_infos(self, packet: Packet):
        '''
        Givin a packet, extract Dropbox infos relative at db-lsp-disc Protocol using class DBlspDISC
        :param packet: ONLY form "pyshark.Filecapture" create with option 'use_json=True'
        :return:
        '''
        name: str
        if ('eth' in packet and 'db-lsp-disc' in packet):
            name = packet.eth.src[:]
        else:
            return

        new_db_lsp_disc: DBlspDISC = DBlspDISC(packet)

        dev: Device = None
        if (name in self._devices):
            dev = self._devices[name]
        else:
            dev = Device(name)

        if ('ip' in packet):
            dev.update_IPv4(packet.ip.src[:])

        if ('ipv6' in packet):
            dev.update_IPv6(packet.ipv6.src[:])

        dev.update_DB(new_db_lsp_disc)

    def process_packet(self, packet: Packet):
        '''
        Useless, because one function allow paket with 'use_json=False', but the other not ...
        :param packet:
        :return:
        '''
        self.extract_mDNS_info(packet)
        self.extract_DB_infos(packet)

    def get_dropbox_subNET(self):
        '''
        It Create and return a 'subnet' of the devices that have namespaces in common
        :return:
        '''
        for d in self._devices.values():
            d:Device
            db_lsp: DBlspDISC = d.get_DB_info()
            if(db_lsp!=None): # this device have Dropbox infos?
                for ns in db_lsp.namespaces():
                    # dict of devices, groupped by namespaces
                    if(ns in self._namespaces_in_common):
                        dev_linked: set = self._namespaces_in_common[ns]
                        dev_linked.add(d.id())
                    else:
                        self._namespaces_in_common[ns]=set()
                        dev_linked:set = self._namespaces_in_common[ns]
                        dev_linked.add(d.id())

        # now
        for ns, linked_devs_MAC in self._namespaces_in_common.items():
            ns:str                  # id of namespace
            linked_devs_MAC:set     # set of all devices's MACs that use 'ns' namespace
            if(len(linked_devs_MAC)>1): # if there are mor than one that announce that namespace
                # build a dict with: key = device's id; value= set of all devices that announce same namespaces
                for dev_MAC_master in linked_devs_MAC:
                    for dev_MAC in linked_devs_MAC:
                        if(dev_MAC_master!=dev_MAC):
                            if(dev_MAC_master in self._dropbox_subNET):
                                all_connections:set = self._dropbox_subNET[dev_MAC_master]
                                all_connections.add(dev_MAC)
                            else:
                                self._dropbox_subNET[dev_MAC_master] = set()
                                all_connections: set = self._dropbox_subNET[dev_MAC_master]
                                all_connections.add(dev_MAC)

        return self._dropbox_subNET

    def print_DB(self):
        print('')
        print('###########################################################')
        print('####################### DropBox Net #######################')
        print('###########################################################')

        dbNet = self.get_dropbox_subNET()
        for dev_MAC, dev_linked in dbNet.items():
            print(dev_MAC, '<--->', dev_linked)


    def all_kind_protocol(self):
        all_Prot: set = set()
        for _d in self._devices.values():
            d: Device = _d
            srvs: dict = d.get_services()
            for _s in srvs.values():
                s: ServiceMDNS = _s
                all_Prot.add(s.protocol())
                if s.protocol() == '':
                    print('', end='')

        try:
            all_Prot.remove('')
        except KeyError:
            pass

        print('')
        print('##################### All*Protocols #####################')
        for p in all_Prot:
            print(p)

    def all_local_alias(self):
        for d in self._devices.values():
            d: Device
            for a in d.aliases():
                a: str
                if (a.count('.local') > 0):
                    print(a.replace('.local', ''))


class WhoIsWhat:
    '''Utility class that try to assign a kind to a device'''
    _device: Device
    ALL: dict = _ALLprot
    SPEC: dict = _SPECprot
    UNKNOWN: str = '???'
    _protos: set
    _bestMatches: set # set of all kinds that should be a real kind of devices
    _kindPool: dict # dictionary where indicate grade of trust of which kind the device could be
    _kind: str # the guessed kind
    _rel_lev: int #
    '''Reliability about what a Device's kind it is. Range value: 1(Unknown) <---> 9(Sure)'''
    _guess_owner: str

    def __init__(self, dev: Device):
        self._protos: set = set()
        self._kindPool = {}
        self._bestMatches = set()
        self._kind = self.UNKNOWN # init kind with 'unknewn' = ???
        self._rel_lev = 0
        self._guess_owner=self.UNKNOWN

        for kind in self.ALL:       # initialize kind-pool, all Kind have reliability 0
            self._kindPool[kind] = 0

        self._device: Device = dev

        self.check()

    def check(self):
        '''Main function to analyze and guessing the kind of device'''
        dev: Device = self._device
        # First, check mDNS recod: 'device-info' => with this record can guess almost surely what is the right kind
        for s in dev.get_services().values():
            s: ServiceMDNS
            self._protos.add(s.protocol())
            if (s.protocol() == '_device-info'):
                info: str = self.check_dev_info(s)
                if (info != None):
                    self._kind = info
                    # self._rel_lev=9

        # Next, try to extract a kind(and maybe a owner) from aliases '.local'
        # Note: the reliability of this guessing is 5/9
        self.check_on_local_alias()

        # At the end, if no device-info was found, try to guess basing from mDNS's services detected
        if (self._rel_lev < 9):
            self.check_MDNS_proto()

    def check_dev_info(self, record: ServiceMDNS):
        '''
        Try to extract TXT infos: 'model' and, if it is present, 'osxvers' \n
        With that infos, it can right guessing the device
        :param record: mDNS record which contain 'device-info'
        :return: right Kind of device: model and, if there is, OsX Version
        '''
        if (record.protocol() != '_device-info'):
            return None
        txts: dict = record.txts() # get a copy
        info = None

        model = None
        if ('model' in txts):
            model = txts.pop('model')

        osx = None
        if ('osxvers' in txts):
            osx = txts.pop('osxvers')

        if (model != None and model in apple_products):
            info = apple_products[model]
            self._rel_lev = 9
        elif (model != None):
            info = 'Model #: ' + model
            self._rel_lev = 9

        if (osx != None and osx in apple_osx_versions):
            info = info + ' with ' + apple_osx_versions[osx]
        elif (osx != None):
            if (info != None):
                info = info + ', OsX: ' + osx
            else:
                info = 'OsX: ' + osx

        if (len(txts) > 0):
            if (info == None):
                info = ''
            for inf in txts:
                info = info + ' = ' + txts[inf] + ', '

            info = info[:len(info) - 3]

        return info

    def check_on_local_alias(self):
        '''
        Try to guess kind and owner of the device, extracting from the 'name' of device, the alias of form 'alias.local'
        :return:
        '''
        for alias in self._device.aliases():
            alias: str
            if (alias.count('.local') > 0):
                # get the name of device
                keyw: str = alias.replace('.local', '')

                # for evrery kind in dict 'keyword_on_alias', get his dict of keywords and search it in a alias/name device's
                for kind, keyword_dict in keyword_on_alias.items():

                    for k in keyword_dict:
                        if (keyw.count(k) > 0):
                            keyw = k
                            break

                    # if a keyword was found => cleanup the name/alias, trying to guess the owner of device
                    if (keyw in keyword_dict):
                        howis = keyword_dict[keyw]
                        #owner = self.purify_str(alias)
                        owner = alias.replace(keyw, '').replace('.local', '')
                        owner = owner.replace('s-', '').replace('-di-', '').replace('-de-', '').replace('-von-', '').replace('-', ' ').replace('.', ' ')
                        #owner = owner.replace('di', '').replace('de', '').replace('von', '')

                        # if len < 3 => maybe the remaining chars are number or not relevant
                        if (len(owner) < 3):
                            owner = self.UNKNOWN
                        self._guess_owner = owner

                        if (self._rel_lev < 5):
                            # add it into the set 'best matches'
                            self._bestMatches.add(howis + ' (supposed by  dev`s name)')
                            self._kindPool[kind] = 5    # indica che il tipo indovinato ha affidabilita' 5
                            self._rel_lev = 5

    def purify_str(self, string:str):
        clear_str:str = string
        for s in keyword_on_alias:
            for k in s:
                clear_str = clear_str.replace(k,'')

        for k in common_string:
            clear_str = clear_str.replace(k,'')
        for k in common_string_s:
            clear_str = clear_str.replace(k,' ')
        return clear_str

    def check_MDNS_proto(self):
        '''
        Try to guess the kind, scanning the services's protocols provide by device
        :return:
        '''
        max: int = 0
        best: str = None
        # First, chek on 'specific sets', where are reported all protocols that can be associated at an a specific kind
        for p in self._protos:
            for kind, kind_set in zip(self.SPEC, self.SPEC.values()):

                if p in kind_set:
                    trust = self.ALL[kind][p][0] # reliability of that sprotocol to guess that kind

                    if (self._kindPool[kind] < trust): # update only if the kind-reliability of that kind is upper than previous
                        self._bestMatches.add(kind)
                        self._kindPool[kind] = trust
                        if (trust > max): # update global level of reliability
                            max = trust
                            self._rel_lev = trust

        if (len(self._bestMatches) == 0 or self._rel_lev <= 5):
            # After, chek on 'generic sets', where are reported all protocols that maybe can be associated at an a kind
            # (similar to 'specific check')
            for p in self._protos:
                for kind, kind_dict in zip(self.ALL, self.ALL.values()):
                    if p in kind_dict:
                        trust = kind_dict[p][0]
                        if (trust > self._kindPool[kind]):
                            self._bestMatches.add(kind)
                            self._kindPool[kind] = trust
                            if (trust > max):
                                max = trust
                                self._bestMatches.add(kind)

    def shared_printer(self):
        '''Identify if the printer is a stand-alone Printer or is a device that share a Printer'''
        if ('PRINTER' in self._bestMatches):
            srvs = self._device.get_services()
            for s in srvs.values():
                s: ServiceMDNS
                # if the 'istance-name' of the service contain a char '@' => the device share that service
                if (s.protocol() in self.ALL['PRINTER'] and s.service().count('@') > 0):
                    self._bestMatches.remove('PRINTER')
                    self._bestMatches.add('Dvice that Share a Printer')
                    break
            '''
            if('PRINTER' in self._bestMatches and len(self._bestMatches)>1):
                self._kind = 'PRINTER or device that share a PRINTER: '
                self._bestMatches.remove('PRINTER')
            '''

    def get_kind(self):
        '''Cleanup the infos about this device and return a best-guessed kind of this device'''

        # if the collected infos are reliable
        if (len(self._bestMatches) > 0 and (self._kind == self.UNKNOWN or self._rel_lev >= 5)):
            self._kind = self._kind.replace(self.UNKNOWN, '')

            if ('PRINTER' in self._bestMatches):
                self.shared_printer()

            # Compose the string that describe a kind guessed
            for b in self._bestMatches:
                if (self._kind == ''):
                    self._kind = b
                else:
                    self._kind = self._kind + ' / ' + b

        return self._kind[:]

    def get_owner(self):
        return str(self._guess_owner)

    def reliability(self):
        '''Reliability about what a Device's kind it is. Range value: 1(Completely Unknown) <---> 9(completely Sure)'''
        return int(self._rel_lev)

    def get_bestMatches(self):
        return list(self._bestMatches)
