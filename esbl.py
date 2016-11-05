#!/usr/bin/python
#
# Broadlink python module by Evgeniy Shumilov <evgeniy.shumilov@gmail.com
#
>
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
            self.cache = {}
            self.exclude = ('86bf0000aa2af58702019c0ed0c51b3475a0d309', '26c200005499c2b90027ccbd581e4794641597a9', '60b320e4c786a7152a368820c1ea4aa35be4ab17')
        else:
            self.__err__('Error: host or port is empty', 1)
        self.filter = 'udp and ether host %s and dst port %s' % (self.mac, self.port)
        self.path = os.path.join(os.getcwd(), 'codes')
        if not os.path.exists(self.path):
            os.mkdir(self.path)

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
                mac = mac[0][0][1].fields['dst']
                print mac
                return mac
            except:
                self.__err__('Error: can\'t get mac address from ip', 2)
        else:
            self.__err__('Error: can\'t get mac address from ip', 2)

    def __pktCheck__(self, pkt):
        #try:
        if pkt[2].name == 'UDP':
            pl = self.__str2hex__(pkt[3].fields['load'])
            ind = pl[-40:]
            if not ind in self.exclude and pl.startswith('5aa5aa555'):
                if not self.c2.has_key(ind):
                    if self.c1.has_key(ind):
                        self.c2[ind] = (self.c1.pop(ind), pl)
                    else:
                        self.c1[ind] = pl
                    print self.c1
                    print
                    print self.c2
                    print '-------'
        #except:
            #self.__wrn__('fail to check sniffed packet')

    @staticmethod
    def compare(code1, code2):
        ''' Compare two codes for similarity '''
        diff = 0
        l = min(len(code1), len(code2))
        for c in xrange(l):
            if code1[c] != code2[c]:
                diff += 1
        if float(l-diff)/l > 0.92:
            return True
        else:
            return False

    def scanCodes(self):
        self.c1 = {}
        self.c2 = {}
        sniff(filter=self.filter, prn=self.__pktCheck__)

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

    def storeCode(self, name):
        if name:
            pkts=sniff(filter=self.filter, count=2)
            res=[]
            res.append(self.__getHexPayload__(pkts[0]))
            res.append(self.__getHexPayload__(pkts[1]))
            self.__saveToFile__(name, res[0] + ' ' + res[1])
            self.__saveToFile__(name + '_l', '0')
            return
        else:
            self.__wrn__('empty code name to save')

    def sendCode(self, name):
        if name:
            codes = self.__loadFromFile__(name)
            last = self.__loadFromFile__(name + '_l')
            if codes and last:
                last = int(last)
                if last:
                    self.__saveToFile__(name + '_l', '0')
                else:
                    self.__saveToFile__(name + '_l', '1')
                self.brs(self.__hex2str__(codes.split(' ')[last]))
            else:
                self.__wrn__('can\'t load code to send')
        else:
            self.__wrn__('empty code name to send')

b = bl('10.11.11.18')

b.scanCodes()

#TODO: Move codes to the devicemac_devicename folders
#TODO: Load codes from filesystem to c1, c2 caches before scan
#TODO: Research method for scan network for detecting broadlink devices
#TODO: Make autosaving codes to the filesystem
#TODO: Device -> scan, rename, list, listcodes
#TODO: Code -> rename, remove, import, export
#TODO: Codes -> import, export, import from dump

