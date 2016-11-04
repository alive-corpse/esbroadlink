#!/usr/bin/python

host='10.11.11.19'
port=80

from os import urandom
from sys import exit
from scapy.all import *

class bl:

    def __init__(self, host, port):
        if host and port:
            self.host = host
            self.port = port
        else:
            print 'Error: host or port is empty'
            sys.exit(1)
        self.path = os.path.join(os.getcwd(), 'codes')
        if not os.path.exists(self.path):
            os.mkdir(self.path)
    
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

    @staticmethod
    def brs(payload):
        if payload:
            p = IP(dst=host)/UDP(dport=port)
            p.add_payload(payload)
            send(p)
        else:
            print 'Warning: empty payload to send'

    @staticmethod
    def __getMacByIp__(ip):
        if ip:
            mac = arping(ip)
            if mac:
                mac = mac[0][1].fields['src']
            else:
                print 'Error: can\'t get mac address from ip'
                exit(2)
        else:
            print 'Error: can\'t get mac address from ip'
            exit(2)


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
            print 'Warning: empty file name for save'
            return ''

    def storeCode(self, name):
        if name:
            pkts=sniff(filter='dst '+self.host+' and port '+str(self.port), count=2)
            res=[]
            res.append(self.__getHexPayload__(pkts[0]))
            res.append(self.__getHexPayload__(pkts[1]))
            self.__saveToFile__(name, res[0] + ' ' + res[1])
            self.__saveToFile__(name + '_l', '0')
        else:
            print 'Warning: empty code name to save'

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
                print 'Warning: can\'t load code to send'
        else:
            print 'Warning: empty code name to send'


#res=sniff(filter='ether host '+mac)
#res=sniff(filter='dst '+host+' and port '+str(port), count=2)

b = bl(host, port)

#b.storeCode('tvok')

test = b.sendCode('tvok')
