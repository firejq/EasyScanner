# -*- coding: utf-8 -*-
# Author： firejq
# Created on 2018-06-17
from host_discovery.host_discovery import HostDiscovery
from port_scanning.port_scanning import PortScanning


class NetScanning:
    def __init__(self, target):
        self.target = target

    def get(self):
        print('start scanning...')
        alive_host = set()

        host_discovery = HostDiscovery(self.target, False).ping()
        while not host_discovery.res_que.empty():
            alive_host.add(host_discovery.res_que.get())
        host_discovery = HostDiscovery(self.target, False).arping()
        while not host_discovery.res_que.empty():
            alive_host.add(host_discovery.res_que.get())
        host_discovery = HostDiscovery(self.target, False).erriping()
        while not host_discovery.res_que.empty():
            alive_host.add(host_discovery.res_que.get())

        print('alive host:')
        alive_host = sorted(alive_host)
        print(alive_host)
        print('\n')

        for host in alive_host:
            print('For ' + host + ':')
            PortScanning(host + ':1-1024').scan()

        print('scanning over')


if __name__ == '__main__':
    NetScanning('192.168.1.0/24').get()
