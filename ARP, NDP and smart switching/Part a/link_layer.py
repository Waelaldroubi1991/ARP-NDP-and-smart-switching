# Wael Aldroubi #
# 300456658 #

#........................................................................#

#!/usr/bin/env python3

from switchyard.lib.userlib import *

class EthernetProcessor():

    def __init__(self, mac, iface):
        self.mac_address = mac
        self.interface = iface
        self.ipv6 = None
        self.physical = None

    def setstack(self, ip, physical):
        self.ipv6 = ip
        self.physical = physical

    def accept_packet(self, packet_data):

        # remove first header
        eth = packet_data.get_header_by_name("Ethernet")
        del packet_data[0]
        #.............................................................................#
        #to process eithernet packets#
        log_debug("packet data in ethernet processor")
        log_debug(packet_data)
        #.............................................................................#
        self.ipv6.accept_packet(packet_data)

    def send_packet(self, packet_data, dst_mac,indicator):

        placeholder = 0xffff
        #.............................................................................#
        #to decide the eithernet type
        if(indicator != 0):
            if(indicator == 1):
                placeholder = 0x0800 #ipv4
            elif(indicator == 2):
                placeholder = 0x86dd #ipv6
        else:
            placeholder = 0x0806 #arp
        #.............................................................................#
        eth = Ethernet(src=self.mac_address, dst=dst_mac, ethertype=placeholder)
        p = Packet() + eth +packet_data
        self.physical.send_packet(self.interface, p)


    def __str__(self):
        return "Ethernet link layer ({})".format(self.ipv6_address)