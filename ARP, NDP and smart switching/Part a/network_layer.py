# Wael Aldroubi #
# 300456658 #

#........................................................................#

#!/usr/bin/env python3

from switchyard.lib.userlib import *

class IpProcessor():

    def __init__(self, inet6, inet4):
        self.ipv6_address = inet6
        self.ipv4_address = inet4
        self.stopandwait = None
        self.ethernet = None
        #.............................................................................#
        # will change hardcode to Dynamic table structure.
        self.ipv6_2mac = dict()
        self.ipv4_2mac = dict()
        #.............................................................................#
    def setstack(self, ethernet, stopandwait):
        self.ethernet = ethernet
        self.stopandwait = stopandwait
        #.............................................................................#
        #Process IP info and pass the packet up the stack
    def accept_packet(self, packet_data):
        #when data recived is asking for my data.
        #to handle IPV4 requests.
        if(packet_data.has_header(IPv4)):   
            ipv4_packet = packet_data.get_header_by_name("IPv4")    
            print("Received IPv4")
            if(ipv4_packet.dst == self.ipv4_address):
                print("Asking for my Ipv4")
                print("Message from: ",ipv4_packet.src)
                print("IPV4 message received passing up to the next layer")
                del packet_data[0]
                self.stopandwait.accept_packet(packet_data,self.ipv4_address)
                #...........................................#
                #when requested data is IPv6
        elif(packet_data.has_header(IPv6)):
            print("Received IPv6")
            ipv6_packet = packet_data.get_header_by_name("IPv6")
            if(ipv6_packet.nextheader == IPProtocol.ICMPv6):
                self.proces_icmpv6(packet_data,ipv6_packet.src,ipv6_packet.dst)
            elif(ipv6_packet.dst == self.ipv6_address):
                print("IPV6 message recived passing to next layer")
                del packet_data[0]
                self.stopandwait.accept_packet(packet_data,self.ipv6_address)
                #...........................................#
                #when requested data is ARP broadcast
        elif(packet_data.has_header(Arp)):     
            arp_packet= packet_data.get_header_by_name("Arp")
            print("ARP Received")
            if(arp_packet.senderprotoaddr not in self.ipv4_2mac):           
                print("New entry to IPv4 map:", arp_packet.senderprotoaddr)
                self.ipv4_2mac[IPv4Address(arp_packet.senderprotoaddr)] = EthAddr(arp_packet.senderhwaddr)
            if(arp_packet.targetprotoaddr == self.ipv4_address):
                #...........................................#
                if(arp_packet.operation == ArpOperation.Reply):    
                    print("Arp operation was a reply")  
                elif(arp_packet.operation == ArpOperation.Request):
                    #...........................................#
                      arp_reply_pkt = self.create_arp_reply(arp_packet)
                      print("Arp operation was a Request")
                      self.ethernet.send_packet(arp_reply_pkt,arp_packet.senderhwaddr,0)
        #.............................................................................#
        #Add IP info and pass the packet down the stack
    def send_packet(self, packet_data, dst_ip):
        #To handle IPV6 requests to find Mac addressof destination
        if type(dst_ip) == type(IPv6Address("0::0")):
            suffix = dst_ip.exploded[-7:] #get the last 6 characters
            broadcast_address = '33:33:ff:'+ suffix[:5] + ":" + suffix[-2:] #Attached the suffix with 33:33:ff
            if dst_ip not in self.ipv6_2mac:
                ipv6_pkt = self.create_ipv6_packet(dst_ip,False)
                ipv6_solicit = self.create_solicitation(dst_ip)
                self.ethernet.send_packet(ipv6_pkt +ipv6_solicit , broadcast_address,2)
            else:
                ipv6_pkt = self.create_ipv6_packet(dst_ip,True)
                self.ethernet.send_packet(ipv6_pkt+packet_data, self.ipv6_2mac[dst_ip],2)
        #...........................................#
        #To handle IPV4 requests to find Mac addressof destination
        elif type(dst_ip) == type(IPv4Address("0.0.0.0")):
            if dst_ip not in self.ipv4_2mac:
               arp_request_pkt= self.create_arp_request(dst_ip)
               self.ethernet.send_packet(arp_request_pkt,"ff:ff:ff:ff:ff:ff",0)
            else:
                ipv4_pkt = IPv4(src= self.ipv4_address,dst=dst_ip)
                self.ethernet.send_packet(ipv4_pkt+packet_data, self.ipv4_2mac[dst_ip],1)
        self.print_map()
    #.............................................................................#
    #To Print the Values and the size of the map when getting mac of IPV4/6
    def print_map(self):  
        if(len(self.ipv6_2mac) !=0):
            #the ipv6_2mac is the dynamic table value instead of the hardocded one.
            print("IPV6 Map size ",len(self.ipv6_2mac))
            for k, v in self.ipv6_2mac.items():
                print("  ",k, v)
        elif(len(self.ipv4_2mac) !=0):
            #the ipv4_2mac is the dynamic table value instead of the hardocded one.
            print("     IPV4 Map size:    ", len(self.ipv4_2mac))
            for k, v in self.ipv4_2mac.items():
                print("  ",k, v)
    #.............................................................................#
    #this function is responsable about creating ARP request to be sent.
    def create_arp_request(self,dst_ip):
        #ARP request is a broadcast "ff:ff:ff:ff:ff:ff".
        arp_request = Arp(operation = ArpOperation.Request,senderhwaddr=self.ethernet.mac_address,
        targethwaddr = "ff:ff:ff:ff:ff:ff",senderprotoaddr=self.ipv4_address, targetprotoaddr=dst_ip)
        return arp_request
    #.............................................................................#
    #This function is responsable about creating ARP reply using the ARP request packet values.
    def create_arp_reply(self,arp_packet):
        arp_reply = Arp(operation=ArpOperation.Reply,senderhwaddr=self.ethernet.mac_address,
        targethwaddr=arp_packet.senderhwaddr,senderprotoaddr=self.ipv4_address,targetprotoaddr=arp_packet.senderprotoaddr)
        return arp_reply
    #.............................................................................#
    #This function is to extract the MAC address
    #will check if the MAC address is in the map
    #If it is solicition will create a replay advertisement to the requestee.
    #if it is advertisement will just print that it received an advertisement.
    #ICMP is responsable about message handling.
    def proces_icmpv6(self,icmpv6_packet,src_ip,dst_ip):         
         icmp_packet = icmpv6_packet.get_header_by_name("ICMPv6")
         mac_address = icmp_packet.icmpdata.options[0]._linklayeraddress
         if src_ip not in self.ipv6_2mac:
                 print(" Added a new entry to IPv6 map:  ", src_ip)
                 self.ipv6_2mac[IPv6Address(src_ip)] = EthAddr(mac_address)
         if(dst_ip == self.ipv6_address):
             if(icmp_packet.icmptype == ICMPv6Type.NeighborSolicitation):
                  print(" ICMPv6 message was a solicitation")
                  ipv6_adver_pkt = self.create_advertisement(src_ip)
                  ipv6_pkt = self.create_ipv6_packet(src_ip,False)
                  self.ethernet.send_packet(ipv6_pkt+ipv6_adver_pkt,mac_address,2)
             else: 
                  print(" ICMPV6 message was an advertisement")
    #.............................................................................#
    #This function is to add ipv6 packet to the map.
    def create_ipv6_packet(self,dst_ip,is_broadcast):
        ipv6 = IPv6(dst=dst_ip,src =self.ipv6_address)
        if(is_broadcast == True):
            #if the broadcast is UDP.
          ipv6.nextheader = IPProtocol.UDP
        else:
          ipv6.nextheader = IPProtocol.ICMPv6
        return ipv6;
    #.............................................................................#
    #This function is to handle solicition and will create a replay advertisement to the requestee.      
    def create_solicitation(self,dst_ip):
        print("  Creating a solicitation packet")
        icmpv6 = ICMPv6(icmptype = ICMPv6Type.NeighborSolicitation)
        icmpv6_solit = ICMPv6NeighborSolicitation(targetaddr=dst_ip)
        icmpv6_solit.options.append(ICMPv6OptionSourceLinkLayerAddress(self.ethernet.mac_address))
        icmpv6.icmpdata = icmpv6_solit
        return icmpv6
    #.............................................................................#
    #This function is to advertisement.         
    def create_advertisement(self,src_ip):
        print("  Creating an advertisement packet")
        icmpv6 = ICMPv6(icmptype=ICMPv6Type.NeighborAdvertisement)
        icmp_advert = ICMPv6NeighborAdvertisement(targetaddr = src_ip)
        icmp_advert.options.append(ICMPv6OptionTargetLinkLayerAddress(self.ethernet.mac_address))
        icmpv6.icmpdata = icmp_advert
        return icmpv6
    #.............................................................................#         
    def __str__(self):
        return "IP network layer ({} & {})".format(self.ipv6_address, self.ipv4_address)

