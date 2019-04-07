from pysnmp.hlapi import *
import sys

import time


#This function do the snmp walk on the specified host and OID. it return lines of the snmp output which relaes to the
# current TCP connection of the printer.
# this function changes the version of SNMO walk when it does not get a valid result from one version

def walk(host, oid):
    output=""
    for (errorIndication,errorStatus,errorIndex,varBinds) in nextCmd(SnmpEngine(),
        CommunityData('public'), UdpTransportTarget((host, 161)), ContextData(),
        ObjectType(ObjectIdentity(oid)),lexicographicMode=False):
        if errorIndication:
            if errorIndication._ErrorIndication__value == 'requestTimedOut':
                for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(SnmpEngine(),
                                                                                    CommunityData('public',mpModel=0),
                                                                                    UdpTransportTarget((host, 161)),
                                                                                    ContextData(),
                                                                                    ObjectType(ObjectIdentity(oid)),
                                                                                    lexicographicMode=False):
                    if errorIndication:
                        print(errorIndication, file=sys.stderr)
                        flag = True
                        break
                    elif errorStatus:
                        print('%s at %s' % (errorStatus.prettyPrint(),
                                            errorIndex and varBinds[int(errorIndex) - 1][0] or '?'),
                              file=sys.stderr)
                        break
                    else:
                        for varBind in varBinds:
                            output = output + str(varBind) + "\n"
            else:
                print(errorIndication, file=sys.stderr)
                break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(),
                                errorIndex and varBinds[int(errorIndex) - 1][0] or '?'),
                                file=sys.stderr)
            break
        else:
            for varBind in varBinds:
                output = output + str(varBind) + "\n"
    return output


# this function reveals which IP address tried to connect to which printer .
# It processes the output of the SNMP walk done by walk function
def extract_relations(lines,verbose):
    relations = []
    for line in lines.split('\n') :
        if line == "":
            continue
        line=line.replace("SNMPv2-SMI::mib-2.6.13.1.2.",'')
        temp = line.split()[0].split('.')
        srcIP = '.'.join(temp[0:4])
        srcPort = temp[4]
        dspIP = '.'.join(temp[5:9])
        dstport = temp[9]
        if not verbose:
            if srcIP in ["0.0.0.0","127.0.0.1"]:
                continue
        relations.append((srcIP,dstport))
        # print (srcIP + ':' + srcPort + '->' + dspIP + ':' + dstport)
    return relations
