WORKSTATION = 'WORKSTATION'
NAS = 'NAS'
PRINTER = 'PRINTER'
MOBILE = 'MOBILE'
MEDIA = 'MEDIA'

_ALLprot: dict = {}
'''
Dictionary where are collected all known protocols, subdivided by kind of device:\n
ex:\t_ALLprot[PC] = set of all protocols detected on 'PC Devices'\n 
Fields: PC, SERVER, PRINTER, MEDIA, MOBILE, ACCESSPOINT
'''

_SPECprot: dict = {}
'''
Like _ALLprot, but every set of protocols contain only the protocols that can be found exclusively in that kind ov Device
Fields: Same of _ALLprot
'''

pWORKSTATION: dict = {
    '_sleep-proxy' : (3, 'AirPort'),
    '_sftp-ssh' : (7, 'Remote Terminal'),
    '_afpovertcp' : (6, 'Apple Filesharing'),
    #'_pdl-datastream' : (3, 'Sharing a Printer'),
    '_net-assistant': (9, 'Apple Remote Desktop'),
    #'_device-info' : (5, 'A generic Device'),
    '_ssh' : (7, 'Remote Terminal'),
    '_workstation' : (9, 'Workstation'),
    '_teamviewer' : (9, 'PC Remote control whith TeamViewer'),
    '_companion-link': (3, 'Sharing & Sync Contacts, Agenda & More'),
    '_smb' : (3, 'Server Message Block'),
    '_rfb' : (8, 'Screen Sharing OSX'),
    '_nomachine': (9, 'Remote Desktop'),
    '_airdrop' : (7, 'Apple File Sharing'),
    '_sketchmirror' : (9, 'PC running Sketch App'),
    '_distcc' : (9, 'Workstation Running a Distribute Compiler'),
    '_eppc' : (9, 'Remote AppleEvents'),
    #'_esdevice',
    #'_esfileshare',
    '_hudson' : (9, 'Workstation Running Jenkins App'),
    '_ichat' : (9, 'Apple PC'),
    '_jenkins' : (9, 'Workstation Running Jenkins App'),
    #'_keynotepair' : (5, 'PC or Mobile with Apple Keynote'),
    '_omnistate' : (9, 'PC running a Omnigroup App'),
    '_photoshopserver': (9, 'Workstation with Photoshop Server'),
    '_raop' : (3, 'Device with Airplay'),
    '_telnet' : (3, 'telnet'),
    '_tunnel' : (1, 'tunnel'),
    '_udisks-ssh' : (6, 'Device with Linux Kernel (Ubuntu/Raspberry Pi)'),
    '_nfs' : (5, 'Workstation using Network File System'),
    '_webdavs' : (3, 'Workstation that offer WebDav instructions'),
    '_apple-sasl' : (9, 'Apple Password Server'),
    '_cloud' : (7, 'Home-Cloud Device (by Daplie)'),
    #'_readynas' : (),
    '_servermgr' : (9, 'Server Admin (Apple)'),
    '_xserveraid' : (9, 'Xserver RAID (Apple)'),
    #'_ftp' : (3, 'Workstation Share Files')
}
_ALLprot['WORKSTATION'] = pWORKSTATION
_SPECprot['WORKSTATION'] = {
    '_net-assistant',
    '_device-info',
    '_workstation',
    '_teamviewer',
    '_smb',
    '_rfb',
    '_nomachine',
    '_sketchmirror',
    '_distcc',
    '_eppc',
    '_hudson',
    '_ichat',
    '_jenkins',
    '_omnistate',
    '_photoshopserver',
    '_raop',
    '_udisks-ssh',
    '_nfs',
    '_webdavs',
    '_apple-sasl',
    '_servermgr',
    '_xserveraid'
}

pNAS: dict = {
    'smb' : (3, 'NAS Share resouces(files, printers, ...)'),
    '_readynas': (9, 'Netgear`s NAS'),
    '_afpovertcp' : (6, 'Apple Filesharing'),
    '_adisk': (9, 'Time Capsule'),
}
_ALLprot['NAS'] = pNAS
_SPECprot['NAS'] = {
    'smb'
    '_readynas',
    '_adisk',
    '_afpovertcp'
}
pPRINTER: dict = {
    '_ipps' : (4, 'Printer'),
    '_pdl-datastream' : (4, 'Printer'),
    '_scanner' : (4, 'Printer'),
    '_ipp' : (4, 'Printer'),
    '_printer' : (4, 'Printer'),
    '_tcp' : (4, 'Printer')
}  # '_ica-networking'
_ALLprot[PRINTER] = pPRINTER
_SPECprot[PRINTER] = {
    '_ipps',
    '_pdl-datastream',
    '_scanner',
    '_ipp',
    '_printer'
}

pMEDIA: dict = {
    '_spotify-connect' : (7, 'Device running Spotify'),
    '_airplay' : (6, 'Device running AirPlay'),
    '_amzn-wplay' : (9, 'Firestick Amazon'),
    '_appletv-v2' : (9, 'Apple TV'),
    '_atc' : (6, 'Device sharing iTunes Library'),
    '_daap' : (8, 'Digital Audio Access Protocol'),
    '_cloud' : (4, 'Daplie`s Device sharing media'),
    '_dpap' : (7, 'Photo Share'),
    '_googlecast' : (9, 'GoogleCast'),
    '_hap' : (8, 'Homekit Apple'),
    '_homekit' : (8, 'Homekit Apple'),
    '_home-sharing' : (6, 'iTunes Sharing'),
    '_mediaremotetv' : (7, 'Apple TV'),
    '_nvstream' : (9, 'NVIDIA Shield'),
    '_raop' : (4, 'Device running Airplay'),
    '_rsp' : (9, 'Roku Server'),
    '_touch-able' : (3, 'Apple TV')
}
_ALLprot[MEDIA] = pMEDIA
_SPECprot[MEDIA] = {
    #'_spotify-connect',
    '_airplay',
    '_amzn-wplay',
    '_appletv-v2',
    '_atc',
    '_daap',
    '_cloud',
    '_dpap',
    '_googlecast',
    '_hap',
    '_homekit',
    '_home-sharing',
    '_mediaremotetv',
    '_nvstream',
    '_raop',
    '_rsp',
    '_touch-able'
}
pMOBILE: dict = {
    '_companion-link' : (5, 'Sharing & Sync Contacts, Agenda & More'),
    '_apple-mobdev2' : (9, 'Device Mobile Apple'),
    '_airdroid' : (9, 'Airdroid App'),
    '_KeynoteControl' : (9, 'Apple Mobile running Keynote'),
    '_keynotepair' : (7, 'Keynote Pair'),
    '_touch-able' : (3, 'Able Touch on Apple TV from Mobile')
}
_ALLprot[MOBILE] = pMOBILE
_SPECprot[MOBILE]={
    '_apple-mobdev2',
    '_airdroid',
    '_KeynoteControl',
    '_keynotepair',
    '_touch-able'
}

pACCESSPOINT: set = {
    '_riousbprint'
}
_ALLprot['ACCESSPOINT'] = pACCESSPOINT

# print('Diff:', pPC.symmetric_difference(pSERVER).intersection(pPC).__len__())#.intersection(pPC)
'''

for i in _ALLprot:
    si: set = _ALLprot[i]
    print("Difference", i, "from ALL:")
    diff: set = si.difference(_ALLprot)
    diff = diff.intersection(si)
    # print(diff)
    for j in _ALLprot:
        if (i != j):
            sj: set = _ALLprot[j]
            # print("Difference", i, "from", j, ":")
            diff = diff.intersection(si.difference(sj).intersection(si))
            # print(diff)
            # print('')
    print(diff)
    _SPECprot[i] = set(diff)
'''

apple_products = {
    'Macmini5,3': 'Mac mini "Core i7" 2.0 (Mid-2011/Server)',
    'Macmini5,2': 'Mac mini "Core i7" 2.7 (Mid-2011)',
    'Macmini5,1': 'Mac mini "Core i5" 2.3 (Mid-2011)',
    'MacPro4,1': 'Mac Pro "Eight Core" 2.93 (2009/Nehalem)',
    'iMac16,2': 'iMac "Core i7" 3.3 21.5-Inch (4K, Late 2015)',
    'iMac16,1': 'iMac "Core i5" 1.6 21.5-Inch (Late 2015)',
    'iMac5,1': 'iMac "Core 2 Duo" 2.33 20-Inch',
    'MacBookPro7,1': 'MacBook Pro "Core 2 Duo" 2.66 13" Mid-2010',
    'MacPro2,1': 'Mac Pro "Eight Core" 3.0 (2,1)',
    'MacBook10,1': 'MacBook "Core i7" 1.4 12" (Mid-2017-18)',
    'Macmini1,1': 'Mac mini "Core Duo" 1.83',
    'iMac12,2': 'iMac "Core i7" 3.4 27-Inch (Mid-2011)',
    'iMac6,1': 'iMac "Core 2 Duo" 2.33 24-Inch',
    'MacBookPro5,1': 'MacBook Pro "Core 2 Duo" 2.93 15" (Unibody)',
    'MacBookPro11,5': 'MacBook Pro "Core i7" 2.8 15" Mid-2015 (DG)',
    'MacBookPro11,4': 'MacBook Pro "Core i7" 2.8 15" Mid-2015 (IG)',
    'MacBookPro11,3': 'MacBook Pro "Core i7" 2.8 15" Mid-2014 (DG)',
    'MacBookPro11,2': 'MacBook Pro "Core i7" 2.8 15" Mid-2014 (IG)',
    'MacBookPro11,1': 'MacBook Pro "Core i7" 3.0 13" Mid-2014',
    'MacBookPro10,2': 'MacBook Pro "Core i7" 3.0 13" Early 2013',
    'MacBookPro10,1': 'MacBook Pro "Core i7" 2.8 15" Early 2013',
    'MacBookPro5,5': 'MacBook Pro "Core 2 Duo" 2.53 13" (SD/FW)',
    'MacBookAir7,1': 'MacBook Air "Core i7" 2.2 11" (Early 2015)',
    'MacBookAir7,2': 'MacBook Air "Core i7" 2.2 13" (Early 2015)',
    'iMac17,1': 'iMac "Core i7" 4.0 27-Inch (5K, Late 2015)',
    'MacBookPro8,1': 'MacBook Pro "Core i7" 2.8 13" Late 2011',
    'MacBookPro8,2': 'MacBook Pro "Core i7" 2.5 15" Late 2011',
    'MacBookPro8,3': 'MacBook Pro "Core i7" 2.5 17" Late 2011',
    'MacBook6,1': 'MacBook "Core 2 Duo" 2.26 13" (Uni/Late 09)',
    'MacBookPro4,1': 'MacBook Pro "Core 2 Duo" 2.6 17" (08)',
    'Macmini4,1': 'Mac mini "Core 2 Duo" 2.66 (Server)',
    'PowerMac10,2': 'Mac mini G4/1.5',
    'PowerMac10,1': 'Mac mini G4/1.42',
    'iMac13,2': 'iMac "Core i7" 3.4 27-Inch (Late 2012)',
    'iMac13,1': 'iMac "Core i3" 3.3 21.5-Inch (Early 2013)',
    'iMac9,1': 'iMac "Core 2 Duo" 2.26 20-Inch (Mid-2009)',
    'Macmini3,1': 'Mac mini "Core 2 Duo" 2.53 (Server)',
    'iMac5,2': 'iMac "Core 2 Duo" 1.83 17-Inch (IG)',
    'MacBook2,1': 'MacBook "Core 2 Duo" 2.16 13" (Black)',
    'MacBook1,1': 'MacBook "Core Duo" 2.0 13" (Black)',
    'iMac14,4': 'iMac "Core i5" 1.4 21.5-Inch (Mid-2014)',
    'iMac14,1': 'iMac "Core i5" 2.7 21.5-Inch (Late 2013)',
    'iMac14,3': 'iMac "Core i7" 3.1 21.5-Inch (Late 2013)',
    'iMac14,2': 'iMac "Core i7" 3.5 27-Inch (Late 2013)',
    'MacBookPro2,2': 'MacBook Pro "Core 2 Duo" 2.33 15"',
    'MacBookAir3,2': 'MacBook Air "Core 2 Duo" 2.13 13" (Late 2010)',
    'MacBookPro13,1': 'MacBook Pro "Core i7" 2.4 13" Late 2016',
    'MacBookPro13,3': 'MacBook Pro "Core i7" 2.9 15" Touch/Late 2016',
    'MacBookPro13,2': 'MacBook Pro "Core i7" 3.3 13" Touch/Late 2016',
    'MacBook9,1': 'MacBook "Core m7" 1.3 12" (Early 2016)',
    'MacBookAir6,1': 'MacBook Air "Core i7" 1.7 11" (Early 2014)',
    'MacBookAir6,2': 'MacBook Air "Core i7" 1.7 13" (Early 2014)',
    'MacBookPro9,1': 'MacBook Pro "Core i7" 2.7 15" Mid-2012',
    'MacBookPro9,2': 'MacBook Pro "Core i7" 2.9 13" Mid-2012',
    'MacBook3,1': 'MacBook "Core 2 Duo" 2.2 13" (Black-SR)',
    'MacPro6,1': 'Mac Pro "Twelve Core" 2.7 (Late 2013)',
    'iMac10,1': 'iMac "Core 2 Duo" 3.33 27-Inch (Late 2009)',
    'MacBookPro1,1': 'MacBook Pro "Core Duo" 2.16 15"',
    'MacBookPro5,3': 'MacBook Pro "Core 2 Duo" 3.06 15" (SD)',
    'MacBookPro5,2': 'MacBook Pro "Core 2 Duo" 3.06 17" Mid-2009',
    'iMac8,1': 'iMac "Core 2 Duo" 3.06 24-Inch (Early 2008)',
    'MacBookPro5,4': 'MacBook Pro "Core 2 Duo" 2.53 15" (SD)',
    'Macmini2,1': 'Mac mini "Core 2 Duo" 2.0',
    'MacBookAir3,1': 'MacBook Air "Core 2 Duo" 1.6 11" (Late 2010)',
    'Macmini6,1': 'Mac mini "Core i5" 2.5 (Late 2012)',
    'MacBookPro1,2': 'MacBook Pro "Core Duo" 2.16 17"',
    'iMac4,1': 'iMac "Core Duo" 2.0 20-Inch',
    'iMac4,2': 'iMac "Core Duo" 1.83 17-Inch (IG)',
    'Macmini7,1': 'Mac mini "Core i7" 3.0 (Late 2014)',
    'MacBookPro2,1': 'MacBook Pro "Core 2 Duo" 2.33 17"',
    'MacBook5,1': 'MacBook "Core 2 Duo" 2.4 13" (Unibody)',
    'MacBook5,2': 'MacBook "Core 2 Duo" 2.13 13" (White-09)',
    'MacBookPro14,2': 'MacBook Pro "Core i7" 3.5 13" Touch/Mid-2017-18',
    'MacBookPro14,3': 'MacBook Pro "Core i7" 3.1 15" Touch/Mid-2017-18',
    'MacPro1,1*': 'Mac Pro "Quad Core" 3.0 (Original)',
    'MacBookPro14,1': 'MacBook Pro "Core i7" 2.5 13" Mid-2017-18',
    'MacBookPro12,1': 'MacBook Pro "Core i7" 3.1 13" Early 2015',
    'MacBook8,1': 'MacBook "Core M" 1.3 12" (Early 2015)',
    'iMac15,1': 'iMac "Core i5" 3.3 27-Inch (5K, Mid-2015)',
    'MacBookAir1,1': 'MacBook Air "Core 2 Duo" 1.8 13" (Original)',
    'MacBookAir2,1': 'MacBook Air "Core 2 Duo" 2.13 13" (Mid-09)',
    'iMac7,1': 'iMac "Core 2 Extreme" 2.8 24-Inch (Al)',
    'MacBookAir5,2': 'MacBook Air "Core i7" 2.0 13" (Mid-2012)',
    'MacBook4,1': 'MacBook "Core 2 Duo" 2.4 13" (Black-08)',
    'MacBookAir5,1': 'MacBook Air "Core i7" 2.0 11" (Mid-2012)',
    'MacBookPro3,1': 'MacBook Pro "Core 2 Duo" 2.6 17" (SR)',
    'iMac11,1': 'iMac "Core i7" 2.8 27-Inch (Late 2009)',
    'iMac11,2': 'iMac "Core i5" 3.6 21.5-Inch (Mid-2010)',
    'iMac11,3': 'iMac "Core i7" 2.93 27-Inch (Mid-2010)',
    'MacBook7,1': 'MacBook "Core 2 Duo" 2.4 13" (Mid-2010)',
    'Macmini6,2': 'Mac mini "Core i7" 2.6 (Late 2012/Server)',
    'MacPro5,1': 'Mac Pro "Twelve Core" 3.06 (Server 2012)',
    'MacBookPro6,2': 'MacBook Pro "Core i7" 2.8 15" Mid-2010',
    'MacBookPro6,1': 'MacBook Pro "Core i7" 2.8 17" Mid-2010',
    'iMac18,1': 'iMac "Core i5" 2.3 21.5-Inch (Mid-2017-18)',
    'iMac18,3': 'iMac "Core i7" 4.2 27-Inch (5K, Mid-2017-18)',
    'iMac18,2': 'iMac "Core i7" 3.6 21.5-Inch (4K, Mid-2017-18)',
    'iMac12,1': 'iMac "Core i3" 3.1 21.5-Inch (Late 2011)',
    'MacBookAir4,2': 'MacBook Air "Core i5" 1.6 13" (Edu Only)',
    'MacBookAir4,1': 'MacBook Air "Core i7" 1.8 11" (Mid-2011)',
    'MacPro3,1': 'Mac Pro "Eight Core" 3.2 (2008)',
    'J81AP': ' iPad Air 2 (iPad5,3 model)',
    'J71bAP': 'iPad (6th generation) (iPad7,5 model)',
    'J82AP' : 'iPad Air 2 (iPad5,4 model)'
}

apple_osx_versions = {
    '4': 'Mac OS X 10.0 (Cheetah)',
    '5': 'Mac OS X 10.1 (Puma)',
    '6': 'Mac OS X 10.2 (Jaguar)',
    '7': 'Mac OS X 10.3 (Panther)',
    '8': 'Mac OS X 10.4 (Tiger)',
    '9': 'Mac OS X 10.5 (Leopard)',
    '10': 'Mac OS X 10.6 (Snow Leopard)',
    '11': 'Mac OS X 10.7 (Lion)',
    '12': 'OS X 10.8 (Mountain Lion)',
    '13': 'OS X 10.9 (Mavericks)',
    '14': 'OS X 10.10 (Yosemite)',
    '15': 'OS X 10.11 (El Capitan)',
    '16': 'OS X 10.12 (Sierra)',
    '17': 'OS X 10.13 (High Sierra)',
}

iPhone = 'iPhone'
iPad = 'iPad Tablet'
PC = 'Personal Computer'
keyword_on_alias = {}
'''
Contain all dictionaries of common keyword on name devices, subdivided by kind(WORKSTATION, MOBILE), ...
\nEx: keyword_on_alias[WORKSTATION] = it contain keyword of form: < 'MacBook-Pro-di-': 'MacBook Pro Notebook' > 
'''

keyword_on_alias[WORKSTATION] = {
    'DESKTOP': 'Windows Desktop',
    's-MacBook-Air': 'MacBook Air Notebook',
    'PC': PC,
    'Computer': PC,
    'MacBook-Pro-di-': 'MacBook Pro Notebook',
    'iMac-di-': 'iMac PC Desktop',
    'iMac': 'iMac PC Desktop',
    's-iMac': 'iMac PC Desktop',
    's-MacBookPro': 'MacBook Pro Notebook',
    's-mac-mini': 'Mac Mini Desktop',
    'Computer-di-': PC,
    'Mac' : 'Mac PC'
}

keyword_on_alias[MOBILE] = {
    'Android': 'Android Device',
    's-iPad': iPad,
    'iPhone-de-': iPhone,
    'iPad-di-': iPad,
    'iPhone': iPhone
}


