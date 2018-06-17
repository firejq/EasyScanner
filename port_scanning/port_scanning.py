# -*- coding: utf-8 -*-
# Author： firejq
# Created on 2018-06-17
from scapy.layers.inet import IP, TCP, UDP, ICMP, RandShort
from scapy.sendrecv import sr

from host_discovery.host_discovery import HostDiscovery


class PortScanning:
    def __init__(self, target):
        if ':' in target:
            sub_target = target.split(':')
            self.ipaddress = sub_target[0]
            if '-' in sub_target[1]:
                ssub_target = sub_target[1].split('-')
                self.lport = int(ssub_target[0])
                self.hport = int(ssub_target[1])
            else:
                self.lport = self.hport = int(sub_target[1])
        else:
            self.ipaddress = target
            self.lport = 0
            self.hport = 65535
        # 定义结果列表
        self.res_ports = []

    def scan(self, method='S'):
        print('start scanning... please wait a minute\n')

        # 首先检测目标主机是否可达
        if HostDiscovery().arping_one(self.ipaddress) == 0:
            print(self.ipaddress + ' cannot be reachable!')
            return 0

        method = method.upper()
        if method == 'S':
            self.syn_scan()
        elif method == 'C':
            self.connect_scan()
        elif method == 'A':
            self.ack_scan()
        elif method == 'U':
            self.udp_scan()

        print('\nscanning over.')
        return self

    def connect_scan(self):
        self.syn_scan(True)

    def syn_scan(self, is_complete_connect=False):
        ans = sr(IP(id=RandShort(), dst=self.ipaddress) /
                 TCP(sport=RandShort(), dport=(self.lport, self.hport),
                     seq=RandShort(), ack=RandShort(), flags='S'),
                 timeout=1, verbose=False)
        if len(ans[0]) > 0:
            for answer in ans[0]:
                port = answer[1][TCP].fields['sport']
                flags = answer[1][TCP].fields['flags']
                if flags == 18:  # 返回 SA，表示端口OPEN
                    if is_complete_connect:  # 是否完成TCP全连接
                        sr(IP(dst=self.ipaddress) /
                           TCP(sport=RandShort(), dport=port, flags='AR'),
                           timeout=1, verbose=False)
                    self.res_ports.append({port: 'OPEN'})
                    print(str(port) + ' is OPEN')
                else:  # 返回 RA，表示端口CLOSED
                    self.res_ports.append({port: 'CLOSED'})
        for unanswer in ans[1]:  # 无任何返回，表示端口被防火墙过滤
            port = unanswer[TCP].fields['dport']
            self.res_ports.append({port: 'FILTERED'})

    def ack_scan(self):  # todo error
        ans, unans = sr(IP(id=RandShort(), dst=self.ipaddress) /
                        TCP(sport=RandShort(), dport=(self.lport, self.hport),
                            seq=RandShort(), ack=RandShort(), flags='A'),
                        timeout=1, verbose=False)
        for s, r in ans:
            if s[TCP].dport == r[TCP].sport:
                port = s[TCP].dport
                self.res_ports.append({port: 'OPEN'})
                print(str(port) + ' is OPEN')
        for s in unans:
            port = s[TCP].dport
            self.res_ports.append({port: 'FILTERED'})

    def udp_scan(self):
        ans, unans = sr(IP(id=RandShort(), dst=self.ipaddress) /
                        UDP(sport=RandShort(),
                            dport=(self.lport, self.hport)),
                        timeout=1, verbose=False)
        if len(ans) > 0:
            for s, r in ans:
                if r.haslayer(ICMP):
                    self.res_ports.append({r[3].fields['dport']: 'CLOSED'})
        for s in unans:
            port = s[UDP].fields['dport']
            self.res_ports.append({port: 'OPEN'})
            print(str(port) + ' is OPEN')


if __name__ == '__main__':
    PortScanning('192.168.1.1:1-1024').scan()
    PortScanning('192.168.1.1:1-1024').scan('u')
