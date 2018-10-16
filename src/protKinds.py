
_ALLprot:dict={}
'''
Dictionary where are collected all known protocols, subdivided by kind of device:\n
ex:\t_ALLprot[PC] = set of all protocols detected on 'PC Devices'\n 
Fields: PC, SERVER, PRINTER, MEDIA, MOBILE, ACCESSPOINT
'''

_SPECprot:dict={}
'''
Like _ALLprot, but every set of protocols contain only the protocols that can be found exclusively in that kind ov Device
Fields: Same of _ALLprot
'''

pPC:set={'_sleep-proxy', '_sftp-ssh', '_adisk', '_afpovertcp', '_pdl-datastream', '_net-assistant',
         '_device-info', '_ssh', '_workstation', '_teamviewer', '_companion-link', '_smb', '_sleep-proxy', '_rfb',
         '_nomachine', '_afpovertcp', '_sftp-ssh', '_net-assistant', '_airdrop', '_sketchmirror', '_distcc', '_eppc',
         '_esdevice', '_esfileshare', '_hudson', '_ichat', '_jenkins', '_keynotepair', '_omnistate', '_photoshopserver',
         '_raop', '_telnet', '_tunnel', '_udisks-ssh'}
_ALLprot['PC']=pPC

pSERVER:set={'_adisk', '_afpovertcp', '_nfs', '_ssh', '_smb', '_webdavs', '_apple-sasl', '_cloud', '_hudson',
             '_jenkins', '_readynas', '_servermgr', '_xserveraid'}
_ALLprot['SERVER']=pSERVER

pPRINTER:set={'_ftp', '_ipps', '_pdl-datastream', '_scanner', '_ipp', '_printer', '_fax-ipp', '_riousbprint',
              '_ica-networking'}
_ALLprot['PRINTER']=pPRINTER

pMEDIA:set={'_spotify-connect', '_airplay', '_amzn-wplay', '_appletv-v2', '_atc', '_daap', '_cloud', '_dpap',
            '_googlecast', '_hap', '_homekit', '_home-sharing', '_mediaremotetv', '_nvstream', '_raop', '_rsp',
            '_touch-able'}
_ALLprot['MEDIA']=pMEDIA

pMOBILE:set={'_companion-link', '_apple-mobdev2', '_airdroid', '_airdrop', '_KeynoteControl', '_keynotepair',
             '_touch-able', '_esdevice', '_esfileshare'}
_ALLprot['MOBILE']=pMOBILE

pACCESSPOINT:set={'_riousbprint', '_airport'}
_ALLprot['ACCESSPOINT']=pACCESSPOINT

#print('Diff:', pPC.symmetric_difference(pSERVER).intersection(pPC).__len__())#.intersection(pPC)

for i in _ALLprot:
    si:set=_ALLprot[i]
    print("Difference", i, "from ALL:")
    diff: set = si.difference(_ALLprot)
    diff=diff.intersection(si)
    #print(diff)
    for j in _ALLprot:
        if(i!=j):
            sj:set=_ALLprot[j]
            #print("Difference", i, "from", j, ":")
            diff=diff.intersection(si.difference(sj).intersection(si))
            #print(diff)
            #print('')
    print(diff)
    _SPECprot[i]=set(diff)

class HowIsWhat:
    ALL:dict=_ALLprot
    SPEC:dict=_SPECprot
    UNKNOWN:str='???'
    _bestMatches:set
    kindPool:dict
    def __init__(self):
        self.kindPool={}
        self._bestMatches=set()
        for kind in self.ALL:
            self.kindPool[kind]=0

    def check(self, protocols:list):
        #prots:list[str]=protocols[:]
        #while(self._bestMatches and len(prots)>0):
        for p in protocols:
            for kind, kind_set in zip(self.SPEC, self.SPEC.values()):
                if p in kind_set:
                    self._bestMatches.add(kind)
                    break

        if(len(self._bestMatches)==0):
            for p in protocols:
                for kind, kind_set in zip(self.ALL, self.ALL.values()):
                    if p in kind_set:
                        self.kindPool[kind]+=1

            max:int=0
            best:str=self.UNKNOWN
            for kind, count in zip(self.kindPool, self.kindPool.values()):
                if(count>max):
                    best=kind
                    max=count
                elif(count==max):
                    best=best + '/' + kind

            self._bestMatches.add(best)

        return list(self._bestMatches)
