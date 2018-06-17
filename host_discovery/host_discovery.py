# -*- coding: utf-8 -*-
# Author： firejq
# Created on 2018-06-17
import ipaddress

from multiprocessing import Queue
from scapy.all import *
from random import randint


class HostDiscovery:
    """
    主机发现
    """

    def __init__(self, target='', verbose=True):
        if target != '':
            self.verbose = verbose
            if self.verbose:
                print('start scanning... please wait a minute\n')
            # 定义待扫描队列
            self.target_que = Queue(maxsize=256)
            # 定义结果队列
            self.res_que = Queue(maxsize=256)
            # 将所有目标 IP 都加入待扫描队列
            ipaddrs = ipaddress.ip_network(target)
            for ip in ipaddrs:
                self.target_que.put(str(ip))

    def ping(self):
        """
        基于ICMP的主机发现
        :return:
        """
        self.__discovery_handler('icmp')
        return self

    def arping(self):
        """
        基于ARP的主机发现
        :return:
        """
        self.__discovery_handler('arp')
        return self

    def erriping(self):
        """
        基于异常IP包的主机发现
        :return:
        """
        self.__discovery_handler('ip')
        return self

    def __discovery_handler(self, method):
        thread_number = 64
        for i in range(thread_number):
            # ICMP包扫描
            if method == 'icmp':
                p = Thread(target=HostDiscovery.ping_process,
                           args=(self, self.target_que, self.res_que))
            # 异常IP包扫描
            elif method == 'ip':
                p = Thread(target=HostDiscovery.erriping_process,
                           args=(self, self.target_que, self.res_que))
            # ARP扫描
            else:
                p = Thread(target=HostDiscovery.arping_process,
                           args=(self, self.target_que, self.res_que))
            p.start()

        while not self.target_que.empty():
            time.sleep(1)

        if self.verbose:
            print('\nscanning over.')

    def arping_process(self, target_queue, res_queue):
        while not target_queue.empty():
            ip = target_queue.get()
            res = HostDiscovery.arping_one(ip)
            if res != 0:
                res_queue.put(ip)
                if self.verbose:
                    print(
                        'IP: ' +
                        res[0][1].getlayer(ARP).fields['psrc'] +
                        ', MAC: ' +
                        res[0][1].getlayer(ARP).fields['hwsrc'] +
                        ' is UP.')

    def ping_process(self, target_queue, res_queue):
        while not target_queue.empty():
            ip = target_queue.get()
            res = HostDiscovery.ping_one(ip)
            if res == 1:
                res_queue.put(ip)
                if self.verbose:
                    print(ip + ': UP')

    def erriping_process(self, target_queue, res_queue):
        while not target_queue.empty():
            ip = target_queue.get()
            res = HostDiscovery.erriping_process_one(ip)
            if res == 1:
                res_queue.put(ip)
                if self.verbose:
                    print(ip + ': UP')

    @staticmethod
    def arping_one(host):
        """
        :param host: 目标主机
        :return: 返回1表示host可达，否则不可达
        """
        ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=host),
                         timeout=1, verbose=False)
        if len(ans) > 0:
            return ans
        else:
            return 0

    @staticmethod
    def ping_one(host):
        """
        :param host: 目标主机
        :return: 返回1表示host可达，否则不可达
        """
        # 随机产生IP包Id
        ip_id = randint(1, 65535)
        # 随机产生ICMP包Id
        icmp_id = randint(1, 65535)
        # 随机产生ICMP包Seq
        icmp_seq = randint(1, 65535)
        ans = sr1(IP(id=ip_id, dst=host, ttl=64) /
                  ICMP(id=icmp_id, seq=icmp_seq) / b'',
                  timeout=1,
                  verbose=False)
        # ans.show()
        if ans:
            return 1
        else:
            return 0

    @staticmethod
    def erriping_process_one(host):
        """
        :param host: 目标主机
        :return: 返回1表示host可达，否则不可达
        """
        # 随机产生IP包Id
        ip_id = randint(1, 65535)
        ans = sr1(IP(id=ip_id, dst=host, ttl=64, proto='esp'),
                  timeout=1,
                  verbose=False)
        # ans.show()
        if ans:
            return 1
        else:
            return 0


if __name__ == '__main__':
    HostDiscovery('192.168.1.0/24').ping()
    HostDiscovery('192.168.1.0/24').arping()
    HostDiscovery('192.168.1.0/24').erriping()
