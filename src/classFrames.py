from pyshark.packet.packet import Packet
from pyshark.packet.fields import *
from discriminators_sets import apple_osx_versions, apple_products, _SPECprot, _ALLprot, keyword_on_alias, common_string, common_string_s, printer_keywords
from DropBox_utils import DBlspDISC
import snmp_utils
import subprocess
import re
import os
import glob
import matplotlib.pyplot as plt
# from ego_analysis_lan import *
from netaddr import IPAddress
from nested_dict import nested_dict
from collections import deque
# from spacy.en import English
import numpy as np
from datetime import datetime,timedelta
from textwrap import wrap


# Print or not info of services
DEBUG_SRV = False
domain_name = ''
slots = []

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
    _label : str    #VZ specifies the label of that node on the graph
    _lastIPv4: str
    _lastIPv6: str
    _services: dict
    _alias: set     # All names that this device have into this LAN
    _db_lsp_disc: DBlspDISC
    _browser_win_version : str # VZ : browser protocol extracted information about version of windows.
    _browser_hostname : str    # VZ : comment section extracted from browser host or master announcement
    _browser_comment : str     # VZ : hostname section extracted from browser host or master announcement
    _dhcp_fqdn : str           # VZ : name extracted from DHCP request
    _db_name : str             # VZ : names resolved from our Database
    _last_DB_timestmp : str    # VZ : The timestamp of the last Dropbox packet seen in the capture
    _category : str

    def __init__(self, dev_id: str, ip: str = ''):
        self._id = str(dev_id)
        self._lastIPv4 = ''
        self._lastIPv6 = ''
        self._services = dict()
        self._alias = set()
        self._kind = ''
        self._owner = '???'
        self._db_lsp_disc = None
        self._browser_win_version = ''
        self._browser_hostname = ''
        self._browser_comment = ''
        self._dhcp_fqdn = ''
        self._db_name = ''
        self._label = ''
        self._last_DB_timestmp = ''
        self._category = ''


    def get_DB_info(self):
        return self._db_lsp_disc

    def browser_hostname(self):
        return self._browser_hostname

    def browser_comment(self):
        return self._browser_comment

    def browser_win_version(self):
        return self._browser_win_version

    def dhcp_info(self):
        return self._dhcp_fqdn

    def id(self):
        return self._id[:]

    def last_IPv4_know(self):
        return self._lastIPv4[:]

    def last_IPv6_know(self):
        return self._lastIPv6[:]

    def label(self):
        return self._label

    def last_DB_timestamp(self):
        return self._last_DB_timestmp

    def set_last_DB_time(self, newtime : str):
        self._last_DB_timestmp = newtime

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

    def db_name(self):
        return str(self._db_name)

    def category(self):
        return self._category

    def set_category(self, newcat : str):
        if newcat is not None:
            self._category = newcat

    def update_IPv4(self, new_ip: str):
        if new_ip != '' and new_ip != None:
            temp = str(new_ip).replace('(','').replace(')','')
            self._lastIPv4 = temp

    def update_IPv6(self, new_ip: str):
        if new_ip != '' and new_ip != None:
            self._lastIPv6 = str(new_ip)

    def update_browser_info(self, new_hostname : str , new_comment : str , new_win_ver : str):
        if str(new_hostname) != '':
            self._browser_hostname = str(new_hostname)
        if str(new_comment) != '':
            self._browser_comment = str(new_comment)
        if str(new_win_ver) != '':
            self._browser_win_version = str(new_win_ver)

    def update_dhcp_info(self, new_hostname : str ):
        self._dhcp_fqdn = str(new_hostname)

    def update_db_name(self,new_db_name : str):
        if new_db_name != "":
            self._db_name = new_db_name


    def set_label(self,newlabel : str):
        newlabel = newlabel.strip()
        newlabel = re.sub(r'\([^)]*\)', '', newlabel)
        newlabel = newlabel.replace(' ','-')
        self._label = newlabel

    def find_category(self):
        #first read self.kind
        for kind, keyword_dict in keyword_on_alias.items():
            for k in keyword_dict:
                k = k.lower()
                if (self.label().lower().count(k) > 0):
                    return kind
                if (self.kind().lower().count(k) > 0):
                    return kind
                if self.browser_win_version().lower().count(k):
                    return kind
                if self.dhcp_info().lower().count(k) > 0 :
                    return kind
                if self.browser_hostname().lower().count(k):
                    return kind
                if self.browser_comment().lower().count(k):
                    return kind
                if self.db_name().lower().count(k):
                    return kind



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
        if self.isunknown(self._kind):
            self._kind = checker.get_kind()
        if self.isunknown(self._owner):
            self._owner = checker.get_owner()

        self.extract_label(checker)


    def isunknown(self,variable : str):
        if variable in ['','???']:
            return True
        else:
            return False

    def extract_label(self,checker):
        keyw = ''
        if not self.isunknown(self._owner):
            self.set_label(self._owner)
            return
        else:
            for alias in self.aliases():
                alias: str
                keyw: str = alias.replace('.local', '').lower()
                if 'PRINTER' in self.kind():
                    if any(x in keyw for x in printer_keywords):
                        self.set_label(keyw)
                        return
                    else:
                        self.set_label(list(self.aliases())[0])
                elif 'NAS' in self.kind():
                    keyw = checker.purify_str(keyw)
                    if any(x in keyw for x in keyword_on_alias['NAS']):
                        self.set_label(keyw)
                    else:
                        self.set_label(keyw)
                elif 'WORKSTATION' in self.kind():
                    keyw: str = alias.replace('.local', '').lower()
                    keyw = checker.purify_str(keyw)
                    if any(x in keyw for x in keyword_on_alias['WORKSTATION']):
                        self.set_label(keyw)
                    if self._label == '':
                        self.set_label(keyw)
                elif self.kind() == 'DropBox Host':
                    self.set_label(self.id() + "[dropbox]")
                else:
                    # first check aliases and then DHCP then browser then Resolved address
                    if len(self.aliases()) > 0:
                        keyw: str = list(self.aliases())[0].replace('.local', '').lower()
                        keyw = checker.purify_str(keyw)
                        self.set_label(keyw)
            if self._label == '':
                if not self.isunknown(self.dhcp_info()):
                    self.set_label(checker.purify_str(self.dhcp_info()))
                elif not self.isunknown(self.browser_hostname()):
                    self.set_label(checker.purify_str(self.browser_hostname()))
                elif not self.isunknown(self.browser_comment()):
                    self.set_label(checker.purify_str(self.browser_comment()))
                elif not self.isunknown(self.db_name()):
                    self.set_label(checker.purify_str(self.db_name()))
                else:
                    self.set_label(self.id())


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


class Link(object):
    ''' Main class represent the connection between two devices'''
    _id : str
    _device_from : Device
    _device_to : Device
    _namespaces_in_common : dict
    _DB_weight : float
    _nbns_frequency_days : list
    _llmnr_frequency_days : list
    _arp_frequency_days : list
    _print_frequency : int
    _weight : int

    def __init__(self, dev_frm : Device , dev_to : Device):
        global slots
        self.id = dev_frm + '-' + dev_to
        self._device_from = dev_frm
        self._device_to = dev_to
        self._namespaces_in_common = list()
        self._DB_weight = 0
        self._nbns_frequency_days = [0] * len(slots)
        self._llmnr_frequency_days = [0] * len(slots)
        self._arp_frequency_days = [0] * len(slots)
        self._print_frequency = 0
        self._weight = 0
    # getters

    def id(self):
        return self._id

    def from_node(self):
        return self._device_from

    def to_node(self):
        return self._device_to

    def nbns_frequency(self):
        return self._nbns_frequency_days

    def llmnr_frequency(self):
        return self._llmnr_frequency_days

    def arp_frequency(self):
        return self._arp_frequency_days

    def get_common_ns(self):
        return self._namespaces_in_common

    def print_frequency(self):
        return self._print_frequency

    def weight(self):
        return self._weight

    def DB_weight(self):
        return self._DB_weight

    # setters

    def set_DB_weight(self,new_weight : float):
        self._DB_weight += new_weight

    def set_weight(self,new_weight : int):
        self._weight = new_weight

    def set_common_ns(self,ns_commons : list):
        self._namespaces_in_common = ns_commons

    def inc_llmnr_frequency(self,day : int):
        try:
            self._llmnr_frequency_days[day] += 1
        except TypeError as e:
            pass

    def inc_nbns_frequency(self,day : int):
        try:
            self._nbns_frequency_days[day] += 1
        except TypeError as e:
            pass

    def inc_arp_frequency(self, day : int):
        try:
            self._arp_frequency_days[day] += 1
        except TypeError as e:
            pass

    def inc_print_frequency(self):
        self._print_frequency += 1


class NetworkLAN:
    '''"Main class", that represents the network under analysis'''
    _devices: dict
    _links : dict
    _lost_srv_propertyes: dict
    _namespaces_in_common:dict
    _dropbox_subNET:dict
    _count_pkt: int
    _mdns_pkt: int
    _browser_pkt: int
    _dhcp_pkt: int
    _dropbox_pkt: int
    _nmap_pkt_update : int
    _nmap_pkt_new : int
    _arp_cache_update_pkt : int
    _arp_cache_new_pkt : int
    _last_30_sec_DB : deque


    def __init__(self):
        self._devices = dict()
        self._links = dict()
        self._lost_srv_propertyes = dict()
        self._namespaces_in_common = dict()
        self._dropbox_subNET = dict()
        self._count_pkt = 0
        self._mdns_pkt = 0
        self._browser_pkt = 0
        self._dhcp_pkt = 0
        self._dropbox_pkt = 0
        self._nmap_pkt_update = 0
        self._nmap_pkt_new = 0
        self._arp_cache_update_pkt = 0
        self._arp_cache_new_pkt = 0
        self._last_30_sec_DB = deque()

    def print_browser_inf(self):
        for _d in self._devices.values():
            d: Device = _d
            print('Device ID: ' +  d.id())
            if d.browser_hostname() != '':
                print('Browser Hostname : ' + d.browser_hostname() )
            if d.browser_comment() != '':
                print('Browser comment : ' + d.browser_comment())
            if d.browser_win_version() != '':
                print('Browser windows version : ' + d.browser_win_version())

    def printAll(self,filename : str):
        ''' Print all infos of the network: devices(MAC addr, aliases, kind, rervices that offer, ...) '''
        counter = 0
        allnames = []
        graph_file = open('lan_graph_{}.txt'.format(filename),'w')
        unknown_counter = 0

        for _d in self._devices.values():
            d: Device = _d
            flag = False
            counter +=1

            print('***************************************')
            print('Device ID: ', d.id())
            if d.last_IPv4_know() != '':
                print("IPv4 Address: " + d.last_IPv4_know())
            if d.last_IPv6_know() != '':
                print("IPv4 Address: " + d.last_IPv6_know())

            print('Aliases: ', end='')
            for al in d.aliases():
                flag= True
                allnames.append(al)
                print(al, end='  || ')
            print('')

            if flag:
                self._mdns_pkt += 1
            d.update_kind()
            print('Who I am: ', d.kind())
            print('Supposed Owner:', d.owner())

            if d.dhcp_info() != '':
                flag=True
                print('DHCP name : ' + d.dhcp_info())
                self._dhcp_pkt += 1
                allnames.append(d.dhcp_info())

            dropbox : DBlspDISC = d.get_DB_info()
            if(dropbox!=None):
                self._dropbox_pkt += 1
                dropbox.print()
                flag = True
            browser_flag = False

            if d.browser_hostname() != '':
                print('Browser Hostname : ' + d.browser_hostname() )
                browser_flag = True
                flag = True
                allnames.append(d.browser_hostname())
            if d.browser_comment() != '':
                browser_flag = True
                print('Browser comment : ' + d.browser_comment())
                flag = True
                allnames.append(d.browser_comment())
            if d.browser_win_version() != '':
                browser_flag = True
                print('Browser windows version : ' + d.browser_win_version())
                flag = True
            if browser_flag:
                self._browser_pkt += 1
            if d.db_name() != '':
                flag = True
                print('Resolved Name : ' + d.db_name())
                allnames.append(d.db_name())
            if d.label() != '':
                print("label : " + str(d.label()))


            if not flag:
                unknown_counter +=1
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
        print("Links between nodes")
        for li in self._links:
            print(str(self._links[li].id) +
                  " : " + str(self._links[li].weight()) +
                  "  [DropBox : " + str(self._links[li].DB_weight()) +
                     " ,LLMNR : "  + str(self._links[li].llmnr_frequency()) +
                     " ,NBNS : "   + str(self._links[li].nbns_frequency()) +
                     " ,ARP : "    + str(self._links[li].arp_frequency()) )
                     # " ,Printer : "+ str(self._links[li].print_frequency()) + "]" )
            dev_from = self._devices[self._links[li]._device_from].label()
            dev_to = self._devices[self._links[li]._device_to].label()
            weight = str(self._links[li].weight())
            graph_file.write(dev_from + " " + dev_to + " " + weight + '\n')

        graph_file.close()

        print("")
        print("Node identification Statistics: ")
        print("\tTotal number of Node Identified : " + str(counter))
        print("\tNumber of MDNS nodes            : " + str(self._mdns_pkt))
        print("\tNumber of Dropbox nodes         : " + str(self._dropbox_pkt))
        print("\tNumber of Browser nodes         : " + str(self._browser_pkt))
        print("\tNumber of DHCP nodes            : " + str(self._dhcp_pkt))
        print("\tNumber of nodes updated by nmap : " + str(self._nmap_pkt_update))
        print("\tNumber of new nodes by nmap     : " + str(self._nmap_pkt_new))
        print("\tNumber of nodes updated by cache: " + str(self._arp_cache_update_pkt))
        print("\tNumber of new nodes by arp cache: " + str(self._arp_cache_new_pkt))
        print("\tNumber of unknown nodes         : " + str(unknown_counter))


    def print_db_graph(self,in_file : str):
        graph_file = open('drpbx_graph_' + in_file + ".txt",  'w')
        for li in self._links:
            print(str(self._links[li].id) + "  [DropBox : " + str(self._links[li].DB_weight()))
            dev_from = self._devices[self._links[li]._device_from]
            dev_from.update_kind()
            dev_from_label = dev_from.label()
            # dev_from = self._links[li]._device_from
            dev_to = self._devices[self._links[li]._device_to]
            dev_to.update_kind()
            dev_to_label = dev_to.label()
            # dev_to = self._links[li]._device_to
            weight = str(self._links[li].DB_weight())

            if dev_from_label != dev_from.id():
                from_label = dev_from_label + '(' + dev_from.id() + ')'
            else:
                from_label = dev_from_label

            if dev_to_label != dev_to.id():
                to_label = dev_to_label + '(' + dev_to.id() + ')'
            else:
                to_label = dev_to_label

            graph_file.write(from_label + " " + to_label + " " + weight + '\n')

        graph_file.close()

    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! EGO ANALYSIS !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    

    def ego_analysis(self):


        for _d in self._devices.values():
            d: Device = _d
            node_cat = d.find_category()
            d.set_category(node_cat)


        base_path = '/root/PycharmProjects/printer_social/BroadMulticast/src/ego_analysis/'
        for filename in os.listdir(base_path):
            files = glob.glob(base_path + filename + '/*')
            for f in files:
                os.remove(f)


        nd = nested_dict(2, list)

        def add_to_nd(threshold, host_from, index):
            nd[threshold][host_from][index] += 1

        def PD_serv_sys_analyze(threshold, type_to, host_from):
            nd.setdefault(threshold, {}).setdefault(host_from, [0] * (6))
            if type_to == "WORKSTATION":
                add_to_nd(threshold, host_from, 0)
            elif type_to == "MOBILE":
                add_to_nd(threshold, host_from, 1)
            elif type_to == "SYSADMIN":
                add_to_nd(threshold, host_from, 2)
            elif type_to == "PHONE":
                add_to_nd(threshold, host_from, 3)
            elif type_to == "NAS":
                add_to_nd(threshold, host_from, 4)
            elif type_to == "PRINTER":
                add_to_nd(threshold, host_from, 5)
            else:
                del nd[threshold][host_from]

        threshold = 0
        for li in self._links:
            host_from = self._links[li].from_node()
            host_to = self._links[li].to_node()
            weight = self._links[li].weight()
            if weight > (threshold):
                type_from = self._devices[host_from].category()
                type_to = self._devices[host_to].category()
                PD_serv_sys_analyze(threshold, type_to, host_from)

        ws_dict = {}
        mob_dict = {}
        sys_dict = {}
        fon_dict = {}
        nas_dict = {}
        prt_dict = {}
        unknown_dict = {}

        def calculate_percent(my_list):
            temp_list = []
            for item in my_list:
                temp_list.append(int(item / sum(my_list) * 100))
            return temp_list

        my_threshold = threshold

        total_ds = 0
        total_ws = 0
        total_mob = 0
        total_sys = 0
        total_fon = 0
        total_nas = 0
        total_prt = 0
        total_unknown = 0

        for id in nd[my_threshold]:
            total_ds += 1
            ttype = self._devices[id].category()
            if ttype == "WORKSTATION":
                total_ws += 1
                ws_dict[id] = calculate_percent(nd[my_threshold][id])
            elif ttype == 'MOBILE':
                total_mob += 1
                mob_dict[id] = calculate_percent(nd[my_threshold][id])
            elif ttype == "SYSADMIN":
                total_sys += 1
                sys_dict[id] = calculate_percent(nd[my_threshold][id])
            elif ttype == "PHONE":
                total_fon += 1
                fon_dict[id] = calculate_percent(nd[my_threshold][id])
            elif ttype == "NAS":
                total_nas += 1
                nas_dict[id] = calculate_percent(nd[my_threshold][id])
            elif ttype == "PRINTER":
                total_prt += 1
                prt_dict[id] = calculate_percent(nd[my_threshold][id])
            else:
                total_unknown += 1
            #     unknown_dict[id] = calculate_percent(nd[my_threshold][id])






        print("")
        print("DataSet Statistics: ")
        print("\tTotal number of Nodes       : " + str(total_ds))
        print("\tNumber of known nodes       : " + str(total_ds - total_unknown))
        print("\tNumber of workstation nodes : " + str(total_ws))
        print("\tNumber of  Mobile nodes     : " + str(total_mob))
        print("\tNumber of  SysAdmin nodes   : " + str(total_sys))
        print("\tNumber of Phone Nodes       : " + str(total_fon))
        print("\tNumber of NAS nodes         : " + str(total_nas))
        print("\tNumber of printer nodes     : " + str(total_prt))
        print("\tNumber of Unknown Nodes     : " + str(total_unknown))

        width = 0.15
        my_lables = 'WORKSTATION', 'MOBILE', 'SYSADMIN', 'PHONE' , 'NAS' , 'PRINTER'
        #
        x_ind = np.arange(len(ws_dict))

        # # Plot
        display_threshold = 30  # this means that each plot should have at most 30 xes.

        counter = 0
        for type_dict in [ws_dict,mob_dict, sys_dict, fon_dict,nas_dict, unknown_dict]:
            partial_lists = []
            my_bins = int(len(type_dict) / display_threshold)
            type_dict_items = list(type_dict.items())
            while len(type_dict_items) > 0:
                cut_index = min(len(type_dict_items), display_threshold)
                partial_lists.append(dict(type_dict_items[:cut_index]))
                del type_dict_items[:cut_index]

            in_counter = 1
            for part_dict in partial_lists:
                ws_values = [item[0] for item in part_dict.values()]
                mob_values = [item[1] for item in part_dict.values()]
                sys_values = [item[2] for item in part_dict.values()]
                fon_values = [item[3] for item in part_dict.values()]
                nas_values = [item[4] for item in part_dict.values()]
                prt_values = [item[5] for item in part_dict.values()]
                # unknown_values = [item[6] for item in part_dict.values()]

                x_ind = range(len(part_dict))
                width = 0.5
                plt.figure(figsize=(25, 10))  # width:20, height:3
                p1 = plt.bar(x_ind, ws_values, color='tab:red', align='edge', width=width)
                p2 = plt.bar(x_ind, mob_values, bottom=ws_values, color='tab:orange', align='edge', width=width)
                p3 = plt.bar(x_ind, sys_values, bottom=[sum(x) for x in zip(ws_values, mob_values)], color='tab:blue',
                             align='edge', width=width)
                p4 = plt.bar(x_ind, fon_values, bottom=[sum(x) for x in zip(ws_values, mob_values,sys_values)], color='tab:pink',
                             align='edge', width=width)
                p5 = plt.bar(x_ind, nas_values, bottom=[sum(x) for x in zip(ws_values, mob_values, sys_values,fon_values)],
                             color='tab:purple', align='edge', width=width)
                p6 = plt.bar(x_ind, prt_values, bottom=[sum(x) for x in zip(ws_values,mob_values, sys_values, fon_values,nas_values)],
                             color='tab:green', align='edge', width=width)
                # p7 = plt.bar(x_ind, unknown_values,
                #              bottom=[sum(x) for x in zip(ws_values, mob_values, sys_values, fon_values, nas_values,prt_values)],
                #              color='tab:brown', align='edge', width=width)

                my_temp = [self._devices[item].label() for item in part_dict.keys()]
                my_temp = ['\n'.join(wrap(l, 10)) for l in my_temp]

                plt.xticks(x_ind, my_temp, rotation='vertical', fontsize=12)

                # plt.legend((p1[0], p2[0], p3[0], p4[0],p5[0],p6[0],p7[0]), (my_lables))
                plt.legend((p1[0], p2[0], p3[0], p4[0],p5[0],p6[0]), (my_lables))

                if counter == 0:
                    out_pic = 'ego_analysis/ws_ego_figures/ws_ego_part' + str(in_counter) + ".png"
                elif counter == 1:
                    out_pic = 'ego_analysis/mob_ego_figures/mob_ego_part' + str(in_counter) + ".png"
                elif counter == 2:
                    out_pic = 'ego_analysis/sys_ego_figures/sys_ego_part' + str(in_counter) + ".png"
                elif counter == 3:
                    out_pic = 'ego_analysis/fon_ego_figures/fon_ego_part' + str(in_counter) + ".png"
                elif counter == 4:
                    out_pic = 'ego_analysis/nas_ego_figures/nas_ego_part' + str(in_counter) + ".png"
                elif counter == 5:
                    out_pic = 'ego_analysis/prt_ego_figures/prt_ego_part' + str(in_counter) + ".png"
                # if counter == 6:
                #     out_pic = 'ego_analysis/unknown_ego_figures/unknown_ego_part' + str(in_counter) + ".png"

                plt.savefig(out_pic)
                plt.clf()
                in_counter += 1

            counter += 1

    def aggregate_links(self):
        global slots
        days = len(slots)
        Dropbox_factor = 6
        # Print_factor = 4
        LLMNR_factor = 2
        NBNS_factor = 2
        ARP_factor = 1
        # factors_sum = Dropbox_factor + Print_factor + LLMNR_factor + NBNS_factor + ARP_factor
        factors_sum = Dropbox_factor + LLMNR_factor + NBNS_factor + ARP_factor
        nd = nested_dict(3, list)
        for li in self._links:
            llink = self._links[li]
            if not all(v == 0 for v in llink._llmnr_frequency_days):
                nd.setdefault('llmnr', {}).setdefault(llink._device_from, {}).setdefault(llink._device_to, llink._llmnr_frequency_days)
            if not all(v == 0 for v in llink._nbns_frequency_days):
                nd.setdefault('nbns', {}).setdefault(llink._device_from, {}).setdefault(llink._device_to, llink._nbns_frequency_days)
            if not all(v == 0 for v in llink._arp_frequency_days):
                nd.setdefault('arp', {}).setdefault(llink._device_from, {}).setdefault(llink._device_to, llink._arp_frequency_days)

        for proto in nd:
            for src in nd[proto]:
                for day in range(0,days):
                    freq_sum = sum([nd[proto][src][item][day] for item in nd[proto][src]])
                    for dst in nd[proto][src]:
                        if proto == 'arp':
                            self._links[src + '-' + dst]._arp_frequency_days[day] = round(nd[proto][src][dst][day]/freq_sum,3)
                        elif proto == 'llmnr':
                            self._links[src + '-' + dst]._llmnr_frequency_days[day] = round(nd[proto][src][dst][day] / freq_sum, 3)
                        elif proto == 'nbns':
                            self._links[src + '-' + dst]._nbns_frequency_days[day] = round(nd[proto][src][dst][day]/freq_sum,3)

        for li in self._links:
            llink = self._links[li]
            weight = (llink.DB_weight() * Dropbox_factor)
                     # (llink.print_frequency() * Print_factor)
            if llink.llmnr_frequency() != [] :
                weight += (np.mean(llink.llmnr_frequency()) * LLMNR_factor)
            if llink.nbns_frequency() != []:
                weight += (np.mean(llink.nbns_frequency()) * NBNS_factor)
            if llink.arp_frequency() !=[]:
                weight += (np.mean(llink.arp_frequency())  * ARP_factor)

            llink._weight = weight / factors_sum

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

        # self._mdns_pkt += 1

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

    def extract_DB_infos_old(self,packet: Packet):
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
            self._devices[name] = dev

        if ('ip' in packet):
            dev.update_IPv4(packet.ip.src[:])

        if ('ipv6' in packet):
            dev.update_IPv6(packet.ipv6.src[:])

        dev.update_DB(new_db_lsp_disc)

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
            self._devices[name]=dev


        if ('ip' in packet):
            dev.update_IPv4(packet.ip.src[:])

        if ('ipv6' in packet):
            dev.update_IPv6(packet.ipv6.src[:])

        dev.update_DB(new_db_lsp_disc)
        pkt_time = str(packet.frame_info.time_epoch)
        dev.set_last_DB_time(pkt_time)
        self.identify_DB_Links(dev)

    def identify_DB_Links(self, dev : Device):
        self._last_30_sec_DB.append((dev,dev.last_DB_timestamp()))
        self.update_queue(dev)
        for item in self._last_30_sec_DB:
            if item[0].id() != dev.id():
                common = [value for value in dev.get_DB_info().namespaces() if value in item[0].get_DB_info().namespaces()]
                if common != []:
                    llink: Link = None
                    link_id = dev.id() + '-' + item[0].id()
                    if (link_id in self._links):
                        llink = self._links[link_id]
                    else:
                        llink = Link(dev.id(), item[0].id())
                        self._links[link_id] = llink
                    llink.set_DB_weight(len(common))
                    llink.set_common_ns(common)

    def update_queue(self,dev : Device):
        if len(self._last_30_sec_DB) == 1 :
            return
        d2 = self._last_30_sec_DB.copy()
        counter = 0
        while counter < len(self._last_30_sec_DB):
            if float(dev.last_DB_timestamp()) - float(d2[counter][1]) > 30:
                self._last_30_sec_DB.pop()
                counter += 1
            else:
                return
        return


    def extract_Browser_info(self,packet: Packet):
        '''
        Givin a packet, extract Browser information
        :param packet: ONLY form "pyshark.Filecapture" create with option 'use_json=True'
        :return:
        '''
        name: str
        if ('eth' in packet and 'browser' in packet):
            name = packet.eth.src[:]
        else:
            return

        dev: Device = None
        if (name in self._devices):
            dev = self._devices[name]
        else:
            dev = Device(name)
            self._devices[name]=dev



        if ('ip' in packet):
            dev.update_IPv4(packet.ip.src[:])

        if ('ipv6' in packet):
            dev.update_IPv6(packet.ipv6.src[:])

        my_data = packet['BROWSER']

        server = ''
        comment = ''
        win_ver = ''
        if str(packet['BROWSER'].command) == '0x00000001':  # Host Announcement
            try:
                server = my_data.server
                comment = my_data.comment
            except AttributeError :
                pass
        elif str(packet['BROWSER'].command) == '0x0000000c':
            server = my_data.mb_server
        elif str(packet['BROWSER'].command) == '0x00000008':  # bowser election Request
            server = my_data.server
        elif str(packet['BROWSER'].command) == '0x00000002':  # Request Announcement
            try:
                server = my_data.response_computer_name
            except AttributeError as e:
                pass
        elif str(packet['BROWSER'].command) == '0x00000009':  # Request Announcement
            pass

        try:
            win_ver = packet.browser.windows_version
        except AttributeError as e:
            pass


        dev.update_browser_info(server,comment,win_ver)


    def form_time_slots(self,filename : str):


        run_output = subprocess.run(['capinfos', filename], stdout=subprocess.PIPE)
        output = run_output.stdout

        for line in output.decode("utf-8").split('\n'):
            if "First packet time:" in line:
                str_time = " ".join(line.split()[-2:])
            elif "Last packet time:" in line:
                end_time = " ".join(line.split()[-2:])
        # print (str_time + " ->" + end_time)

        str_time = str_time.split(',')[0]
        start_time = datetime.strptime(str_time, '%Y-%m-%d %H:%M:%S')

        end_time = end_time.split(',')[0]
        finish_time = datetime.strptime(end_time, '%Y-%m-%d %H:%M:%S')

        duration = finish_time - start_time

        # zero_day = datetime.datetime(start_time.year, start_time.month, start_time.day, 0, 0, 0, 0)
        last_day = datetime(finish_time.year, finish_time.month, finish_time.day, 0, 0, 0, 0)

        global slots

        my_date = start_time
        while my_date < finish_time:
            next_day = datetime(my_date.year, my_date.month, my_date.day, 23, 59, 59, 0)
            if next_day.weekday() < 5:  # Just consider the working days of the week
                slots.append((my_date.timestamp(), min(next_day.timestamp(), finish_time.timestamp())))
            one_sec = timedelta(seconds=1)
            my_date = next_day + one_sec


    def calculate_slot(self,pkt_time):
        global slots
        counter = 0
        for item in slots:
            if float(pkt_time) > item[0] and float(pkt_time) < (item[1] + 1.0):
                return counter
            else:
                counter += 1

    def extract_nbns_infos(self,packet: Packet):
        '''
                Givin a packet, extract DHCP information
                :param packet: ONLY form "pyshark.Filecapture" create with option 'use_json=True'
                :return:
        '''
        name: str
        if ('eth' in packet and 'nbns' in packet):
            name = packet.eth.src[:]
        else:
            return

        dev: Device = None
        if (name in self._devices):
            dev = self._devices[name]
        else:
            dev = Device(name)
            self._devices[name] = dev

        if ('ip' in packet):
            dev.update_IPv4(packet.ip.src[:])

        if ('ipv6' in packet):
            dev.update_IPv6(packet.ipv6.src[:])


        try:
            dest_hostname = packet.nbns.name
            dest_hostname = dest_hostname.replace('<00>','')
            dest_id = self.find_equivalent_node_hostname(dest_hostname)
            if dest_id != None:
                llink: Link = None
                link_id = dev.id() + '-' + dest_id.id()
                if (link_id in self._links):
                    llink = self._links[link_id]
                else:
                    llink = Link(dev.id(), dest_id.id())
                    self._links[link_id] = llink
                pkt_time = str(packet.frame_info.time_epoch)
                day_index = self.calculate_slot(pkt_time)
                llink.inc_nbns_frequency(day_index)
        except AttributeError as e:
            pass
        except UnboundLocalError as e:
            pass

    def find_equivalent_node_ip(self, ip : str):
        for _d in self._devices.values():
            d: Device = _d
            if d.last_IPv4_know() == str(ip) :
                return d

        return None


    def find_equivalent_node_hostname(self,hostname : str):
        hostname = hostname.lower()

        for _d in self._devices.values():
            d: Device = _d
            for al in d.aliases():
                if al.lower() == hostname:
                    return d

            if d.dhcp_info() != '':
                if hostname == d.dhcp_info().lower():
                    return d

            if d.browser_hostname().lower() == hostname:
                return d

            if d.browser_comment().lower() == hostname:
                return d

            if d.db_name().lower() == hostname:
                return d
        return None

    def extract_llmnr_infos(self,packet: Packet):
        '''
        Givin a packet, extract DHCP information
        :param packet: ONLY form "pyshark.Filecapture" create with option 'use_json=True'
        :return:
        '''
        name: str
        if ('eth' in packet and 'llmnr' in packet):
            name = packet.eth.src[:]
        else:
            return

        dev: Device = None
        if (name in self._devices):
            dev = self._devices[name]
        else:
            dev = Device(name)
            self._devices[name] = dev

        if ('ip' in packet):
            dev.update_IPv4(packet.ip.src[:])

        if ('ipv6' in packet):
            dev.update_IPv6(packet.ipv6.src[:])
        try:
            dest_hostname = packet.llmnr.dns_qry_name
        except AttributeError as e:
            pass

        if dest_hostname == 'wpad':
            pass
            #analyze wpad
        else:
            dest_id = self.find_equivalent_node_hostname(dest_hostname)
            if dest_id != None:
                llink: Link = None
                link_id = dev.id() + '-' + dest_id.id()
                if (link_id in self._links):
                    llink = self._links[link_id]
                else:
                    llink = Link(dev.id(), dest_id.id())
                    self._links[link_id] = llink
                pkt_time = str(packet.frame_info.time_epoch)
                day_index = self.calculate_slot(pkt_time)
                llink.inc_llmnr_frequency(day_index)

    def extract_ARP_Links(self, packet : Packet):
        name: str
        if ('eth' in packet and 'arp' in packet ):
            name = packet.eth.src[:]
        else:
            return

        my_data = packet['ARP']
        src_ip = my_data.src_proto_ipv4
        dst_ip = my_data.dst_proto_ipv4


        # IP addresses which are related to sysadmin : '146.48.96.3','146.48.96.1','146.48.96.2','146.48.98.155' ,'192.168.100.1'
        if src_ip == '0.0.0.0' or src_ip.startswith('169.254'):
            return
        if dst_ip == '0.0.0.0' or dst_ip.startswith('169.254'):
            return
        if src_ip == dst_ip:
            return
        dev: Device = None
        if (name in self._devices):
            dev = self._devices[name]
        else:
            dev = Device(name)
            self._devices[name] = dev

        dev.update_IPv4(str(packet.arp.src_proto_ipv4))

        dst_node = self.find_equivalent_node_ip(dst_ip)
        if dst_node != None:
            llink: Link = None
            link_id = dev.id() + '-' + dst_node.id()
            if (link_id in self._links):
                llink = self._links[link_id]
            else:
                llink = Link(dev.id(), dst_node.id())
                self._links[link_id] = llink
            pkt_time = str(packet.frame_info.time_epoch)
            day_index = self.calculate_slot(pkt_time)
            if day_index != None:
                llink.inc_arp_frequency(day_index)

    def extract_DHCP_info(self,packet: Packet):
        '''
        Givin a packet, extract DHCP information
        :param packet: ONLY form "pyshark.Filecapture" create with option 'use_json=True'
        :return:
        '''
        global domain_name
        name: str
        if ('eth' in packet and ('bootp' in packet or 'dhcpv6' in packet)):
            name = packet.eth.src[:]
        else:
            return

        dev: Device = None
        if (name in self._devices):
            dev = self._devices[name]
        else:
            dev = Device(name)
            self._devices[name]=dev


        if ('ip' in packet):
            dev.update_IPv4(packet.ip.src[:])

        if ('ipv6' in packet):
            dev.update_IPv6(packet.ipv6.src[:])

        hostname = ''
        if 'bootp' in packet:
            my_data = packet['bootp']
            try:
                hostname = my_data.option_hostname
            except AttributeError:
                try:
                    hostname = my_data.fqdn_name
                except AttributeError:
                    pass
        else:
            my_data = packet['dhcpv6']
            try:
                hostname = my_data.client_fqdn
            except AttributeError:
                pass

        dev.update_dhcp_info(hostname)

        try:
            if int(my_data.option_dhcp) == 1:
                #DHCP discover => no information
                pass
            elif int(my_data.option_dhcp) == 2:
                #DHCP offer
                # we can keep the information about the requester from destination of these packets.
                dev: Device = None
                name = packet.eth.dst
                if (name in self._devices):
                    dev = self._devices[name]
                else:
                    dev = Device(name)
                    self._devices[name] = dev
                dev.update_IPv4(packet.ip.dst[:])
            elif int(my_data.option_dhcp) == 3:
                #DHCP Request
                pass
            elif int(my_data.option_dhcp) == 5:
                #DHCP ACK
                dev: Device = None
                name = packet.eth.dst
                if (name in self._devices):
                    dev = self._devices[name]
                else:
                    dev = Device(name)
                    self._devices[name] = dev
                dev.update_IPv4(packet.ip.dst[:])
            elif int(my_data.option_dhcp) == 8:
                #DHCP inform
                pass
        except AttributeError:
            pass

        # inspect ACK and offer DHCP packet types to get information about network
        # this case happens for offer and ACK packet types of DHCP protocol
        try:
            dhcp_server = str(my_data.option_dhcp_server_id)
            dhcp_server_node = self.find_equivalent_node_ip(dhcp_server)
            if dhcp_server_node is not None:
                dhcp_server_node.set_label("DHCP_Server")
                if (dhcp_server_node._kind == ''):
                    dhcp_server_node._kind = 'Sysadmin'
                else:
                    dhcp_server_node._kind = dhcp_server_node._kind + ' / ' + 'Sysadmin'
        except AttributeError:
            pass

        try:
            dns_server = str(my_data.option_domain_name_server)
            dns_server_node = self.find_equivalent_node_ip(dns_server)
            if dns_server_node is not None:
                dns_server_node.set_label("DNS_Server")
                if (dns_server_node._kind == ''):
                    dns_server_node._kind = 'Sysadmin'
                else:
                    dns_server_node._kind = dns_server_node._kind + ' / ' + 'Sysadmin'
        except AttributeError:
            pass

        try:
            router = str(my_data.option_router)
            router_node = self.find_equivalent_node_ip(router)
            if router_node is not None:
                router_node.set_label("Router")
                if (router_node._kind == ''):
                    router_node._kind = 'Sysadmin'
                else:
                    router_node._kind = router_node._kind + ' / ' + 'Sysadmin'
        except AttributeError:
            pass

        try:
            ntp_server = str(my_data.option_ntp_server)
            ntp_server_node = self.find_equivalent_node_ip(ntp_server)
            if ntp_server_node is not None:
                ntp_server_node.set_label("NTP_Server")
                if (ntp_server_node._kind == ''):
                    ntp_server_node._kind = 'Sysadmin'
                else:
                    ntp_server_node._kind = ntp_server_node._kind + ' / ' + 'Sysadmin'
        except AttributeError:
            pass

        try:
            domain_name = str(my_data.option_domain_name)
            if not domain_name.startswith('.'):
                domain_name = '.' + domain_name
        except AttributeError:
            pass


    def is_empty(self,any_structure):
        if any_structure:
            print('Structure is not empty.')
            return False
        else:
            print('Structure is empty.')
            return True


    def active_probing(self):
        unknowns = []
        # command = '''tshark -r {} -T fields -e ip.src -e ip.dst | tr "\t" "\n" | sort | uniq '''.format(filename)

        command = 'ifconfig'
        result = subprocess.run(command.split(),stdout=subprocess.PIPE,shell=True)
        output = result.stdout.decode()
        for line in output.split('\n'):
            if 'broadcast' in line:
                local_ip = line.split()[1]
                netmask = line.split()[3]
                broadcast_ip = line.split()[-1]
                break

        cidr = IPAddress(netmask).netmask_bits()
        command = 'nmap -sP {}/{}'.format(local_ip,cidr)
        result = subprocess.run(command.split(),stdout=subprocess.PIPE)
        output = result.stdout.decode()
        hostname = ''
        for line in output.split('\n'):
            if "Nmap scan report" in line:
                if hostname != '':
                    if (Mac_addr in self._devices):
                        self._nmap_pkt_update +=1
                        dev = self._devices[Mac_addr]
                    else:
                        self._nmap_pkt_new += 1
                        dev = Device(Mac_addr)
                        self._devices[Mac_addr] = dev
                    dev.update_db_name(hostname)
                    dev.update_IPv4(ip_addr)
                ip_addr = line.split()[-1].replace('(', '').replace(')', '')
                hostname = line.split()[-2]
            elif "MAC Address" in line:
                Mac_addr = line.split()[2]


        # now the arp cache is filled !! we can search through it to convert mac to IP address
        #

        command = 'ping -b {}'.format(broadcast_ip)
        try:
            subprocess.run(command.split(), stdout=subprocess.PIPE,timeout=15)
        except subprocess.TimeoutExpired:
            pass
        command = 'arp -a'
        arp_result = subprocess.run(command.split(), stdout=subprocess.PIPE)
        output = arp_result.stdout.decode()
        lines = output.split('\n')[:-1]


        for line in lines:
            hostname = line.split()[0]
            line_mac = line.split()[3]
            line_ip = line.split()[1]
            if (line_mac in self._devices):
                self._arp_cache_update_pkt += 1
                dev = self._devices[line_mac]
            else:
                self._arp_cache_new_pkt += 1
                dev = Device(line_mac)
                self._devices[line_mac] = dev
            if hostname != '?':
                dev.update_db_name(hostname)
            dev.update_IPv4(line_ip)



    def process_packet(self, packet: Packet):
        '''
        Useless, because one function allow paket with 'use_json=False', but the other not ...
        :param packet:
        :return:
        '''
        self.extract_mDNS_info(packet)
        self.extract_DB_infos(packet)

    def find_dropbox_relations(self):
        db_nodes = []
        for d in self._devices.values():
            d:Device
            db_lsp: DBlspDISC = d.get_DB_info()
            if(db_lsp!=None): # this device have Dropbox infos?
                db_nodes.append((db_lsp,d))
        nd = nested_dict(2, list)
        for i in range(0,len(db_nodes)):
            for j in range(0,len(db_nodes)):
                if i < j :
                    common = [value for value in db_nodes[i][0].namespaces() if value in db_nodes[j][0].namespaces()]
                    if common!= []:
                        nd.setdefault(db_nodes[i][1].id(),{}).setdefault(db_nodes[j][1].id(),common)
        return nd

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

    def find_printers(self):
        printers = []
        for d in self._devices.values():
            d:Device
            d.update_kind()
            if 'PRINTER' in d.kind():
                printers.append(d)

        return printers

    def extract_snmp_info(self):
        printers = self.find_printers()
        for printer in printers :
            output = snmp_utils.walk(printer.last_IPv4_know(), 'iso.3.6.1.2.1.6.13.1.2')
            relations = snmp_utils.extract_relations(output,False)
            for item in relations:
                src_node = self.find_equivalent_node_ip(item[0])
                dst_node = self.find_equivalent_node_ip(item[1])
                if dst_node != None and src_node != None:
                    llink: Link = None
                    link_id = src_node.id() + '-' + dst_node.id()
                    if (link_id in self._links):
                        llink = self._links[link_id]
                    else:
                        llink = Link(src_node.id(), dst_node.id())
                        self._links[link_id] = llink
                    llink.inc_print_frequency()


    def extract_DB_links(self):
        # print('')
        # print('###########################################################')
        # print('####################### DropBox Net #######################')
        # print('###########################################################')

        dbNet = self.find_dropbox_relations()
        all_dropboxers = set()
        nd = nested_dict(2, float)

        for dev_MAC in dbNet:
            all_dropboxers.add(dev_MAC)
            for dev_linked in dbNet[dev_MAC]:
                all_dropboxers.add(dev_linked)
                llink: Link = None
                link_id = dev_MAC + '-' + dev_linked
                if ( link_id in self._links):
                    llink = self._links[link_id]
                else:
                    llink = Link(dev_MAC, dev_linked)
                    self._links[link_id] = llink

                llink.set_common_ns(dbNet[dev_MAC][dev_linked])
                nd.setdefault(dev_MAC,{}).setdefault(dev_linked , 0)
                nd[dev_MAC][dev_linked] = len(dbNet[dev_MAC][dev_linked]) / len(self._devices[dev_MAC]._db_lsp_disc._namespaces)
                #llink.set_DB_weight(len(dbNet[dev_MAC][dev_linked]))

        self.calculate_DB_weight(llink,nd,len(all_dropboxers))

    def calculate_DB_weight(self, llink : Link,nd : nested_dict,num_all_DB_nodes : int):
        namespace_freq = {}
        all_ns = set()
        for li in self._links:
            for ns in self._links[li]._namespaces_in_common:
                all_ns.add(ns)
                try:
                    namespace_freq[ns] += 1
                except KeyError:
                    namespace_freq[ns] = 1
        num_links = len(self._links)
        P = {} #dictionary for keeping P for each ns
        for ns in all_ns:
            P[ns] = ( num_all_DB_nodes - (namespace_freq[ns] -1) ) / num_all_DB_nodes

        for li in self._links:
            numenator = 0
            if len(self._links[li]._namespaces_in_common) == 0:
                continue
            for ns in self._links[li]._namespaces_in_common:
                numenator += P[ns]
            dev_from = self._links[li]._device_from
            dev_to = self._links[li]._device_to
            nd[dev_from][dev_to] = nd[dev_from][dev_to] * (numenator / len(self._links[li]._namespaces_in_common))
            self._links[li].set_DB_weight(nd[dev_from][dev_to])


    def all_kind_protocol(self):
        all_Prot: set = set()
        for _d in self._devices.values():
            d: Device = _d
            srvs: dict = d.get_services()
            for _s in srvs.values():
                s: Service
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
    _label: str
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


    def get_label(self):
        return self._label

    def kind(self):
        return self._kind

    def isunknown(self,variable : str):
        if variable in ['',self.UNKNOWN]:
            return True
        else:
            return False

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


        self.check_against_dict(dev.dhcp_info(),False)
        self.check_against_dict(dev.browser_hostname(),False)
        self.check_against_dict(dev.browser_comment(),False)
        self.check_against_dict(dev.db_name(),False)
        self.check_against_dict(dev.browser_win_version(), True)


        if (dev.get_DB_info()!=None):
            self._bestMatches.add('DropBox Host')



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
                    owner = self.purify_str(alias)
                    #owner = alias.replace(keyw, '').replace('.local', '')
                    #owner = owner.replace('s-', '').replace('-di-', '').replace('-de-', '').replace('-von-', '').replace('-', ' ').replace('.', ' ')
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

    def check_against_dict(self,keyw : str,browser_os : bool):
        if keyw == '' or keyw is None:
            return
        initial_str = keyw
        initial_str = initial_str.replace(domain_name,'')

        if not browser_os:
            if not (self.isunknown(self._guess_owner) or len(self._bestMatches) == 0) :
                return

        # for evrery kind in dict 'keyword_on_alias', get his dict of keywords and search it in a alias/name device's
        for kind, keyword_dict in keyword_on_alias.items():
            for k in keyword_dict:
                if (keyw.count(k) > 0):
                    keyw = k
                    break

            # if a keyword was found => cleanup the name/alias, trying to guess the owner of device
            if (keyw in keyword_dict):
                howis = keyword_dict[keyw]

                if not browser_os:
                    owner = self.purify_str(initial_str)
                    # owner = alias.replace(keyw, '').replace('.local', '')
                    # owner = owner.replace('s-', '').replace('-di-', '').replace('-de-', '').replace('-von-', '').replace('-', ' ').replace('.', ' ')
                    # owner = owner.replace('di', '').replace('de', '').replace('von', '')

                    # if len < 3 => maybe the remaining chars are number or not relevant
                    if (len(owner) < 3):
                        owner = self.UNKNOWN
                    self._guess_owner = owner

                if (self._rel_lev < 5):
                    # add it into the set 'best matches'
                    self._bestMatches.add(howis + ' (supposed by  dev`s name)')
                    self._kindPool[kind] = 5  # indica che il tipo indovinato ha affidabilita' 5
                    self._rel_lev = 5

    def purify_str(self, string:str):
        global domain_name
        clear_str:str = string
        clear_str = clear_str.replace(domain_name,'')

        for s in keyword_on_alias.values():
            for k in s:
                clear_str = clear_str.replace(k,'')
        for k in common_string:
            clear_str = clear_str.replace(k,'')
        for k in common_string_s:
            clear_str = clear_str.replace(k,' ')

        if clear_str in ['','.','-','_',' ']:
            clear_str = string
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
