from pyshark.packet.packet import Packet
from pyshark.packet.fields import *
from src.discriminators_sets import apple_osx_versions, apple_products, _SPECprot, _ALLprot, keyword_on_alias


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
        self._service=''
        self._protocol=''
        self._domain=''
        self.__dissect_fullname()
        if (service != '' or protocol != '' or domain != ''):
            self.update_SRV_detail(service, protocol, domain)

    def __dissect_fullname(self):
        full:list=self._full_name.rsplit('.',3)
        if(len(full)>3):
            self.update_SRV_detail(full[0],full[1],full[2]+'.'+full[3])
        else:
            i:int=len(full)-1
            dom:str = ''
            proto:str=''
            istance:str=''
            if i >= 0:
                dom = full[i]
                i-=1
            if i >= 0:
                dom = full[i] + '.' + dom
                i -= 1
            if i >= 0:
                proto = full[i]
                i -= 1
            if i >= 0:
                istance = full[i]
                i -= 1
            self.update_SRV_detail(istance,proto,dom)


    # GETTERS:
    def name(self):
        return self._full_name[:]

    def service(self):
        cp=self._service[:]
        return cp

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

        if(self._service=='' and service!=''):
            self._service = service
        if(self._protocol=='' and protocol!=''):
            self._protocol = protocol
        if(self._domain=='' and domain!=''):
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
        if(txt==None or txt==''):
            return
        eql_pos:int = txt.find('=')
        if eql_pos>0 :
            key = txt[:eql_pos]
            val = txt[eql_pos + 1:]
            self._txts[key] = val
        else:
            key = str('info-'+str(self._txts.__len__()))
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
    _id:str
    _kind:str
    _lastIPv4:str
    _lastIPv6: str
    _services:dict
    _alias:set

    def __init__(self, dev_id:str, ip:str=''):
        self._id = str(dev_id)
        self._lastIPv4=''
        self._lastIPv6=''
        self._services=dict()
        self._alias=set()
        self._kind=''

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
            #self.add_alias(new_serv.service())

            for trg_v in new_serv.targets().values():
                trg:Target=trg_v
                for p in trg.ports():
                    serv.add_target(trg.name(),p)

            serv.add_txts(new_serv.txts())

    def remove_service(self,srv: ServiceMDNS):
        '''
        Remove srv from the device services and return it
        :param srv:
        :return:
        '''
        srv_to_rem:str=srv.name()
        return self._services.pop(srv_to_rem)

    def add_alias(self, new_alias: str):
        if(new_alias!=None and new_alias!=''):
            self._alias.add(str(new_alias))

    def update_kind(self):
        protos:set=set()
        checker: HowIsWhat = HowIsWhat(self)

        kindList:list=checker.get_bestMatches()
        self._kind=kindList.pop(0)
        while(len(kindList)>0):
            self._kind=self._kind + '/' + kindList.pop(0)


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
        return  str(self._kind)


class NetworkLAN:
    _devices:dict
    _lost_srv_propertyes:dict

    def __init__(self):
        self._devices=dict()
        self._lost_srv_propertyes=dict()

    def printAllAlias(self):
        for _d in self._devices.values():
            d:Device=_d
            print('***************************************')
            print('Device ID: ',d.id())
            print('Aliases: ',end='')
            for al in d.aliases():
                print(al,end='  || ')
            print('')

            d.update_kind()
            print('How I am: ',d.kind())

            for _srv in d.get_services().values():
                srv:ServiceMDNS=_srv
                print('\t> ', srv.name())
                #print('\t   ', srv.service(),'.',srv.protocol(),'.',srv.domain(),sep='')
                for trg in srv.targets():
                    print('\t   Target',)
                    print('\t          --->',trg)
                txts:dict=srv.txts()
                if(txts.__len__()>0):
                    print('\t   Txts')
                    print('\t   ',end='')
                    for txt_k in txts:
                        print(txt_k,'=',txts[txt_k],sep='',end=' , ')
                    print('')



            print('/----------------------------------/')

    def add_lost_property(self, lost_srv:ServiceMDNS):
        _targets:set = lost_srv.targets()
        if not (len(_targets) > 0):
            _fictitious_trg = lost_srv.service()
            # use where srv recorn has no targets, and dont knew how provide the service
            _targets[_fictitious_trg] = Target(_fictitious_trg, -1)

        for trg in _targets:
            if(trg in self._lost_srv_propertyes):
                _lost_srvs:list=self._lost_srv_propertyes[trg]
                _lost_srvs.append(lost_srv)
            else:
                self._lost_srv_propertyes[trg]=list()
                _lost_srvs: list = self._lost_srv_propertyes[trg]
                _lost_srvs.append(lost_srv)

    def search_lost_propertyes(self, owner:str, device:Device):
        _owner:str = owner
        dev_to_update:Device=None

        if(_owner in self._lost_srv_propertyes):
            dev_to_update=device
        else:
            _dev_aliases: set = device.aliases()
            for alias in _dev_aliases:
                if ( alias in self._lost_srv_propertyes ):
                    dev_to_update=device
                    _owner=alias
        if(dev_to_update!=None):
            _lost_srvs:list = self._lost_srv_propertyes[_owner]
            while(len(_lost_srvs)>0):
                _srv:ServiceMDNS = _lost_srvs.pop(0)
                device.update_services(_srv)


    def cleanup(self, device: Device):
        for _srv in device.get_services().values():  # TODO: Verificare che la 'remove***' non dia problemi al for (nondovrebbe perche' la .get_services() return una copia
            _srv: ServiceMDNS
            _targets = _srv.targets()
            if not(len(_targets)>0):
                _fictitious_trg = _srv.service()
                # use where srv recorn has no targets, and dont knew how provide the service
                _targets[_fictitious_trg]=Target(_fictitious_trg, -1)
            for _trg in _targets:
                if not (_trg in device.aliases()):
                    _lost: ServiceMDNS = device.remove_service(_srv)  # remove***
                    trg_dev = None
                    for _device in self._devices.values():
                        _device: Device
                        _aliases: set = _device.aliases()
                        if ( (_trg in _aliases) ):
                            trg_dev = _device
                            break

                    if (trg_dev != None):
                        trg_dev.update_services(_lost)
                    else:
                        self.add_lost_property(_lost)


    def new_knowledge(self, packet: Packet):
        name:str
        if ('eth' in packet and
                'mdns' in packet and
                #'dns_count_answers' in packet.mdns and
                packet.mdns.dns_count_answers.hex_value>0):
            name = packet.eth.src.show[:]
        else:
            return

        try:
            answ_len:int = int(packet.mdns.dns_resp_name.all_fields.__len__())
        except AttributeError:
            return

        dev: Device = None
        if (name in self._devices):
            dev = self._devices[name]
        else:
            dev = Device(name)
            #self._devices[name] = dev

        if(name=='08:60:6e:e5:91:a8'):
            #print('DBG',end='')
            print('', end='')

        def update(disp:Device, srv_record:ServiceMDNS):
            _dev: Device = None
            for _trgt in srv_record.targets():
                trgt:str=_trgt
                als:set=disp.aliases()
                if (als.__contains__(trgt)):
                    disp.add_alias(srv_record.service())
                    _dev = disp
                    break
            if (_dev != None):
                _dev.update_services(srv_record)
            else:
                _dev = disp
                for _trgt in srv_record.targets():
                    for _d in self._devices.values():
                        d: Device = _d
                        if (d.aliases().__contains__(_trgt) ): #or d.aliases().__contains__(srv_record.service())
                            d.add_alias(srv_record.service())
                            _dev = d
                            break
                _dev.update_services(srv_record)


        if ('ip' in packet):
            dev.update_IPv4(packet.ip.src.show)

        if('ipv6' in packet):
            dev.update_IPv6(packet.ipv6.src.show)

        if ('mdns' in packet and answ_len>0):
            resp_names: list = packet.mdns.dns_resp_name.all_fields[:]
            resp_types: list = packet.mdns.dns_resp_type.all_fields[:]
            resp_lens: list = packet.mdns.dns_resp_len.all_fields[:]
            try:
                txts: list = packet.mdns.dns_txt.all_fields[:]
                txts.reverse()
                txts_len: list = packet.mdns.dns_txt_length.all_fields[:]
                txts_len.reverse()
            except AttributeError:
                txts:list=[]
                txts_len:list=[]
            try:
                addr_a: list = packet.mdns.dns_a.all_fields[:]
            except AttributeError:
                addr_a: list = []
            try:
                addr_aaaa: list = packet.mdns.dns_aaaa.all_fields[:]
            except AttributeError:
                addr_aaaa: list = []
            try:
                srv_servs:list = packet.mdns.dns_srv_service.all_fields[:]
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

            aaaa_list:list=[]
            alias_list:list=[]

            #for i in range(0, resp_names.__len__()):
            while(resp_names.__len__()>0):

                srv = None
                _typ: LayerField = resp_types.pop(0)#resp_types[i]
                r_len:int = int(resp_lens.pop(0).showname_value)
                _nam: LayerField = None
                if(_typ.hex_value!=33): # is not present response name if type in SRV(33)
                    _nam: LayerField = resp_names.pop(0)  # resp_names[i]

################### DEBUG ################################
                # Trigger debug breakpoints: set condition on 'if' and breakpoint on next line
                if(_nam!=None):
                    dbg_str: str = _nam.showname_value
                    if (dbg_str.count('XXXX') > 0 or dev.id()=='08:60:6e:e5:91:a8'):
                        #print('DBG', dbg_str)
                        print('', end='')
                if(_typ.hex_value==33):
                    #print('DBG', _typ.hex_value)
                    print('', end='')
#######################################################
                if (_typ.hex_value == 16):
                    srv = ServiceMDNS(_nam.showname_value)
                    #r_len = int(resp_lens[i].showname_value)
                    while (r_len > 0 and (txts.__len__()>0 and txts_len.__len__()>0)):
                        _len:int= int(txts_len.pop().showname_value)+1
                        r_len -=  _len
                        txt:str=txts.pop().showname_value
                        if(txt!=''): srv.add_txt(txt)

                elif (_typ.hex_value == 1 and addr_a.__len__()>0):
                    a: LayerField = addr_a.pop(0)
                    alias: LayerField = _nam #resp_names[i]
                    if (a.showname_value == dev.last_IPv4_know()):
                        dev.add_alias(alias.showname_value)
                        self.search_lost_propertyes(alias.showname_value, dev)
                    else:
                        for _d in self._devices.values():
                            d:Device = _d
                            if (a.showname_value == str(d.last_IPv4_know())):
                                d.add_alias(alias.showname_value)
                                self.search_lost_propertyes(alias.showname_value, d)
                            elif(alias.showname_value in d.aliases()):
                                d.update_IPv4(a.showname_value)
                                #self.search_lost_propertyes(alias.showname_value, d)
                elif (_typ.hex_value == 28 and addr_aaaa.__len__()>0):
                    aaaa_list.append(addr_aaaa.pop(0))
                    alias_list.append(_nam)

                if (srv != None and dev != None):
                    update(dev,srv)

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
                    update(dev,srv)

            while(aaaa_list.__len__()>0):
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
                        # if (aaaa.showname_value == str(d.last_IP_know())):
                        if (_aaaa == _ip):
                            d.add_alias(alias.showname_value)
                            self.search_lost_propertyes(alias.showname_value, d)
                        elif (alias.showname_value in d.aliases()):
                            d.update_IPv6(_aaaa)
                            #self.search_lost_propertyes(alias.showname_value, d)

        self.cleanup(dev)

        if(len(dev.aliases())>0 or len(dev.get_services())>0):
            self._devices[name] = dev
            #for _srv in dev.get_services().values():
                #dev.add_alias(_srv.service())
                #dev.add_alias('?_' + _srv.service() + '_?')


    def all_kind_protocol(self):
        all_Prot:set=set()
        for _d in  self._devices.values():
            d:Device=_d
            srvs:dict=d.get_services()
            for _s in srvs.values():
                s:ServiceMDNS=_s
                all_Prot.add(s.protocol())
                if s.protocol() == '':
                    print('',end='')

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
            d:Device
            for a in d.aliases():
                a:str
                if(a.count('.local')>0):
                    print(a.replace('.local',''))

class HowIsWhat:
    _device:Device
    ALL: dict = _ALLprot
    SPEC: dict = _SPECprot
    UNKNOWN: str = '???'
    _protos: set
    _bestMatches: set
    _kindPool: dict
    _kind:str
    _rel_lev:int
    '''Reliability about what a Device's kind it is. Range value: 1(Unknown) <---> 9(Sure)'''
    _guess_owner:str

    def __init__(self, dev:Device):
        self._protos:set=set()
        self._kindPool = {}
        self._bestMatches = set()
        self._kind=self.UNKNOWN
        self._rel_lev=0

        for kind in self.ALL:
            self._kindPool[kind] = 0

        self._device:Device=dev

        self.check()

    def check(self):
        dev:Device=self._device
        for s in dev.get_services().values():
            s: ServiceMDNS
            self._protos.add(s.protocol())
            if (s.protocol() == '_device-info'):
                info: str = self.check_dev_info(s)
                if (info != None):
                    self._kind=info
                    self._rel_lev=9

        self.check_on_local_alias()

        if (len(self._bestMatches) == 0):
            self.check_MDNS_proto()

    def check_dev_info(self, record:ServiceMDNS):
        if(record.protocol()!='_device-info'):
            return None
        info=None
        txts:dict=record.txts()
        model=txts['model']
        if(model in apple_products):
            info=apple_products[model]
            if('osxvers' in txts):
                osx = txts['osxvers']
                if(osx in apple_osx_versions):
                    info = info + ' with ' + apple_osx_versions[osx]
        return info

    def check_on_local_alias(self):
        for alias in self._device.aliases():
            alias:str
            if(alias.count('.local')>0):
                keyw:str=alias.replace('.local','')

                for k in keyword_on_alias:
                    if(keyw.count(k)>0):
                        keyw = k #keyword_on_alias[k]
                        break

                if (keyw in keyword_on_alias):
                    howis = keyword_on_alias[keyw]
                    owner = alias.replace(keyw,'').replace('.local','')
                    owner = owner.replace('s-','').replace('-',' ')
                    owner = owner.replace('di','').replace('de','').replace('von','')
                    if(len(owner) < 3):
                        owner=self.UNKNOWN
                    self._guess_owner=owner
                    if(self._rel_lev<5):
                        self._kind=howis
                        self._rel_lev=5

    def check_MDNS_proto(self):
        # prots:list[str]=protocols[:]
        # while(self._bestMatches and len(prots)>0):
        for p in self._protos:
            for kind, kind_set in zip(self.SPEC, self.SPEC.values()):
                if p in kind_set:
                    self._bestMatches.add(kind)
                    break

        if (len(self._bestMatches) == 0):
            for p in self._protos:
                for kind, kind_set in zip(self.ALL, self.ALL.values()):
                    if p in kind_set:
                        self._kindPool[kind] += 1

            max: int = 0
            best: str = self.UNKNOWN
            for kind, count in zip(self._kindPool, self._kindPool.values()):
                if (count > max):
                    best = kind
                    max = count
                elif (count == max and max>0):
                    best = best + '/' + kind

            self._bestMatches.add(best)

        return list(self._bestMatches)

    def get_bestMatches(self):
        return list(self._bestMatches)