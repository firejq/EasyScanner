# -*- coding: utf-8 -*-
# Author： firejq
# Created on 2018-06-17

import sys
import getopt

from auto_work.net_scanning import NetScanning
from host_discovery.host_discovery import HostDiscovery
from port_scanning.port_scanning import PortScanning


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "ht:d:s:a",
                                   ["help", "target=", "discovery=",
                                    "scan=", "auto"])
    except getopt.GetoptError:
        sys.exit(2)
    target = ''
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print('''usage:
    -d <icmp/arp/ip> -t <target>: host discovery
    -s <S/A/C/U> -t <target>/<target:port>/<target:lport-hport>: ports scanning
    -a -t <targe>: auto scanning the target net''')
            sys.exit()
        elif opt in ("-t", "--target"):
            target = arg
            break

    for opt, arg in opts:
        if opt in ("-d", "--discovery"):
            if arg == 'icmp':
                HostDiscovery(target).ping()
            elif arg == 'ip':
                HostDiscovery(target).erriping()
            else:
                HostDiscovery(target).arping()
            sys.exit(0)
        elif opt in ("-s", "--scan"):
            if arg == 'S':
                PortScanning(target).syn_scan()
            elif arg == 'C':
                PortScanning(target).connect_scan()
            elif arg == 'A':
                PortScanning(target).ack_scan()
            elif arg == 'U':
                PortScanning(target).udp_scan()
            sys.exit(0)
        elif opt in ("-a", "--auto"):
            NetScanning(target).get()
            sys.exit(0)


if __name__ == '__main__':
    # usage:
    # main.py -d <icmp/arp/ip> -t <target>
    # main.py -s <S/A/C/U> -t <target>/<target:port>/<target:lport-hport>
    # main.py -a -t <target>
    main(sys.argv[1:])
