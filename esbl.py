#!/usr/bin/python
#
# Broadlink python module by Evgeniy Shumilov <evgeniy.shumilov@gmail.com
#

import re
from os import urandom
from sys import exit
from scapy.all import *
from datetime import datetime

class bl:

    def __init__(self, host, port=80, debug=False):
        self.debug = debug
        if host and port:
            if re.match('^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', host):
                self.mac = host
            elif  re.match('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                mac = self.__getMacByIp__(host)
            self.host = host
            self.port = port
            self.mac = mac
            self.pref='5aa5aa555aa5aa55000000000000000000000000000000000000000000000000'
            self.exclude = ('86bf0000aa2af58702019c0ed0c51b3475a0d309', '26c200005499c2b90027ccbd581e4794641597a9', '60b320e4c786a7152a368820c1ea4aa35be4ab17')
        else:
            self.__err__('Error: host or port is empty', 1)
        self.filter = 'udp and ether host %s and dst port %s' % (self.mac, self.port)
        self.path = os.path.join(os.getcwd(), 'codes')
        if not os.path.exists(self.path):
            os.mkdir(self.path)
        self.path = os.path.join(os.getcwd(), 'codes', self.mac)
        if not os.path.exists(self.path):
            os.mkdir(self.path)
        self.codes = self.loadCodes()
        self.scanned = []
        

    @staticmethod
    def __err__(msg, code=0):
        print datetime.strftime(datetime.now(), '%Y.%m.%d %H:%M:%S'), "Error:", msg
        if code:
            exit(code)

    @staticmethod
    def __wrn__(msg):
        print datetime.strftime(datetime.now(), '%Y.%m.%d %H:%M:%S'), "Warning:", msg

    @staticmethod
    def __str2hex__(s):
        lst = []
        for ch in s:
            hv = hex(ord(ch)).replace('0x', '')
            if len(hv) == 1:
                hv = '0'+hv
            lst.append(hv)
        return reduce(lambda x,y:x+y, lst)

    @staticmethod
    def __hex2str__(pl):
        res = ''
        for c in xrange(len(pl)/2):
            map = {'0': 0, '1':1, '2':2, '3':3, '4':4, '5':5, '6':6, '7':7, '8':8, '9':9,
                    'a':10, 'b':11, 'c':12, 'd':13, 'e':14, 'f':15}
            b = pl[c*2:c*2+2]
            res += chr(map[b[0]]*16+map[b[1]])
        return res

    @staticmethod
    def __randomHex__(length=4):
        res = ''
        map = {0: '0', 1:'1', 2:'2', 3:'3', 4:'4', 5:'5', 6:'6', 7:'7', 8:'8', 9:'9', 10:'a',
            11:'b', 12:'c', 13:'d', 14:'e', 15:'f'}
        for i in xrange(length):
            res += map[random.randint(0,15)]
        return res

    @staticmethod
    def __getPayload__(packet):
        if packet:
            if 'load' in packet[3].fields.keys():
                return packet[3].fields['load']

    def __getHexPayload__(self, packet):
        return self.__str2hex__(self.__getPayload__(packet))

    def brs(self, payload):
        if payload:
            p = IP(dst=self.host)/UDP(dport=self.port)
            p.add_payload(payload)
            send(p)
        else:
            self.__wrn__('empty payload to send')

    def __getMacByIp__(self, ip):
        if ip:
            mac = arping(ip)
            try:
                mac = mac[0][0][1].fields['src']
                return mac
            except:
                self.__err__('Error: can\'t get mac address from ip', 2)
        else:
            self.__err__('Error: can\'t get mac address from ip', 2)

    def __pktCheck__(self, pkt):
        try:
            if pkt[2].name == 'UDP':
                pl = self.__str2hex__(pkt[3].fields['load'])
                ind = pl[-40:]
                code = pl[72:78]+pl[84:]
                if not ind in self.exclude and pl.startswith(self.pref):
                    if not code in self.codes.values():
                        self.scanned.append(code)
                        self.codes[code] = code
                        self.storeCode(code)
                        print 'Got new code:', code
        except:
            self.__wrn__('fail to check sniffed packet')

    @staticmethod
    def compare(code1, code2):
        ''' Compare two codes for similarity '''
        indexes = []
        l = min(len(code1), len(code2))
        for c in xrange(l):
            if code1[c] != code2[c]:
                indexes.append(c)
        print "Indexes:", indexes
        if float(l-len(indexes))/l > 0.92:
            return True
        else:
            return False

    def __saveToFile__(self, name, cont):
        if name and cont:
            f = open(os.path.join('codes', name), 'w')
            f.write(cont)
            f.close()
            return True
        else:
            print 'Warning: empty content or name of file to content saving'
            return False

    def __loadFromFile__(self, name):
        if name:
            f = open(os.path.join('codes', name), 'r')
            res = f.read()
            f.close()
            return res
        else:
            self.__wrn__('empty file name for save')
            return ''

    def scanCodes(self):
        self.scanned = []
        sniff(filter=self.filter, prn=self.__pktCheck__)

    def loadCodes(self):
        codes = {}
        for fn in os.listdir(self.path):
            codes[fn] = self.__loadFromFile__(os.path.join(self.path, fn))
        return codes

    def makeCode(self, pl):
        return self.pref + self.__randomHex__() + '0000' + pl[0:6] + '00' + self.__randomHex__() + pl[6:]

    def storeCode(self, code, name=''):
        if name:
            nm = name[:]
        else:
            nm = code
        if code:
            self.__saveToFile__(os.path.join(self.path, nm), code)
        return nm

    def sendCode(self, name):
        if name:
            if self.codes.has_key(name):
                code = self.codes[name]
            else:
                code = name
            self.brs(self.__hex2str__(self.makeCode(code)))
        else:
            self.__wrn__('empty code name to send')

    def renameCode(self, oldname, newname):
        if oldname and newname and os.path.exists(os.path.join(self.path, oldname)):
            os.rename(os.path.join(self.path, oldname), os.path.join(self.path, newname))
            self.codes[newname] = self.codes.pop(oldname)
        else:
            self.__wrn__('file name for renaming is empty or file not exists')

    def removeCode(self, name):
        if name:
            pth = os.path.join(self.path, name)
            if os.path.exists(pth):
                os.remove(pth)
            if self.codes.has_key(name):
                code = self.codes[name]
                if code in self.scanned:
                    self.scanned.remove(code)
                self.codes.pop(name)
        else:
            self.__wrn__('empty code name to remove')

    def showCode(self, name):
        if name:
            if self.codes.has_key(name):
                print name, self.codes[name]
            else:
                print "Code with this name is hot exists"
        else:
            self.__wrn__('empty code name to show')

b = bl('10.11.11.19')

#TODO: Research method for scan network for detecting broadlink devices
#TODO: Device -> scan, rename, list, listcodes
#TODO: Code -> import, export
#TODO: Codes -> import, export, import from dump

