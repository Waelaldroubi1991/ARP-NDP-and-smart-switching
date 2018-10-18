# Wael Aldroubi #
# 300456658 #

#........................................................................#

#!/usr/bin/env python3

'''
    This exercise is written for NWEN302.
    It is intended to demonstrate link-layer address resolution in IPv6.

    For information about the processes please look into:
      * http://tools.ietf.org/html/rfc4443
      * https://en.wikipedia.org/wiki/Neighbor_Discovery_Protocol

    This file handles setting up the the network stack and receiving from the physical layer.
'''

import os
import json

from switchyard.lib.userlib import *

from data_application import DataApplication
from data_application import Ipv
from transport_layer import StopAndWait
from network_layer import IpProcessor
from link_layer import EthernetProcessor
import preferences

def main(net):

    ''' Assumes either the first or a single interface is to be used '''
    network_interface = net.interfaces()[0]
    iface_name = network_interface.name
    iface_mac = network_interface.ethaddr
    host_ipv6_address = get_ipv6_addr(iface_name)
    host_ipv4_address = network_interface.ipaddr

    print("IPv6 is being disabled **IN MININET HOST** to prevent rogue NDP messages")
    os.system("sysctl net.ipv6.conf.{}.disable_ipv6=1".format(iface_name))  # disable IPv6

    neighbors = generate_neighbor_list(preferences.Preferences, {"ipv4":host_ipv4_address, "ipv6":host_ipv6_address})
    print("Neighbouring IPv4 nodes are:\n    {}".format("\n    ".join(str(x) for x in neighbors["ipv4"])))
    print("Neighbouring Ipv6 nodes are:\n    {}".format("\n    ".join(str(x) for x in neighbors["ipv6"])))

    ''' Attach the new header class correctly '''
    IPv6.add_next_header_class(IPProtocol.StopAndWait, StopAndWaitHeader)
    IPv6.set_next_header_class_key('nextheader')

    IPv4.add_next_header_class(IPProtocol.StopAndWait, StopAndWaitHeader)
    IPv4.set_next_header_class_key('protocol')

    ''' Setup layer objects and bridges between each '''
    app = DataApplication(neighbors=neighbors, ip_version=Ipv.ipv4)
    saw = StopAndWait(inet6=host_ipv6_address, inet4=host_ipv4_address)
    ip = IpProcessor(inet6=host_ipv6_address, inet4=host_ipv4_address)
    ethernet = EthernetProcessor(mac=iface_mac, iface=iface_name)

    app.setstack(transport=saw)
    saw.setstack(ip=ip, app=app)
    ip.setstack(ethernet=ethernet, stopandwait=saw)
    ethernet.setstack(physical=net, ip=ip)

    while True:
        ''' Check/Receive traffic from the network interface '''

        app.run()
        saw.run()
        try:
            timestamp,dev,packet = net.recv_packet(timeout=1.0)
            ethernet.accept_packet(packet)
        except NoPackets:
            continue
        except Shutdown:
            break

def get_ipv6_addr(prefs, iface):
    ''' Uses IFCONFIG to retrieve link-local ipv6 address
        https://stackoverflow.com/a/38394394 '''

    cmd_output = os.popen('ip addr show {}'.format(iface.name)).read()
    if "inet6" in cmd_output:
        inet6 = cmd_output.split("inet6 ")[1]
        addr= inet6.split("/")[0]

    else:
        # ipv6 is disabled, so just make up the address based on the mininet host name
        if not iface.name.startswith("h"):
            # not running mininet....
            print("WARNING YOU AREN'T RUNNING MININET. IPv6 ADDRESSES MAY NOT WORK AS EXPECTED")
            print("**ALSO** YOUR IPV6 MAY NOW BE DISABLED. RUN:\n"\
                "    sysctl net.ipv6.conf.{}.disable_ipv6=0\nTO RE-ENABLE".format(iface.name))
        host_id = str(iface.ipaddr).split(".")[3]
        addr = "{}{}".format(prefs.network_prefix_v6, host_id)

    return ip_address(addr)

def generate_neighbor_list(prefs, this_host):
    neighbors = {"ipv4":[], "ipv6":[]}

    for i in range(0,int(prefs.number_of_hosts)):
        as_str_v4 = "{}{}".format(prefs.network_prefix_v4, i+1)
        as_str_v6 = "{}{}".format(prefs.network_prefix_v6, i+1)
        neighbors["ipv4"].append(IPv4Address(as_str_v4))
        neighbors["ipv6"].append(IPv6Address(as_str_v6))

    if this_host["ipv4"] in neighbors["ipv4"]:
        neighbors["ipv4"].remove(this_host["ipv4"])

    if this_host["ipv6"] in neighbors["ipv6"]:
        neighbors["ipv6"].remove(this_host["ipv6"])

    return neighbors

