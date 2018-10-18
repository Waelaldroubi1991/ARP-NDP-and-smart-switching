# Wael Aldroubi#
#300456658#
#NWEN 302 Lab2 Part2#

'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
#....................................................................................................................#
#Variables used to the MAC address of the interfaces.
#time to live variable
TLL = 255 
# Variable to check if the list of MACs is full.
MAX_DICT_SIZE = 2
#Variable to store the MAC addresses list.
intf_mac = dict()
#....................................................................................................................#
# This code control and update time to live for each device.
# The source device reset to 225 while other entries TTl decreased by 5.
def update_tll(src_hdw_addr):
    for intf,tup in intf_mac.items():
           mac_addr = tup[0]
           tll = tup[1]
           if mac_addr == src_hdw_addr:
               print("increased ttl")
               tll = 255
           else:
               print("decreased tt")
               tup[1] = tup[1]-5
    print(intf_mac)
#....................................................................................................................#
# This code is responsable about checking if the MAC address of a device is in the list. it is used in the main function.
def isInMap(src_hdw_addr):
    for intf, tup in intf_mac.items(): 
        if tup[0]==src_hdw_addr:
            return True
#....................................................................................................................#
# This code if the list is full.
# If it is full, will traverse the list and remove the one with the shortest TTL.
def check_dict_size():
    if len(intf_mac) == MAX_DICT_SIZE:
        longest_tll = 0
        shortest_tll = 255
        eth_tll = 0 
        for intf,tup in intf_mac.items():
            longest_tll = tup[1]
            if(longest_tll <= shortest_tll):
                shortest_tll = longest_tll
                print("shortest", shortest_tll)
                eth_tll = intf #get the corresponding inteface so that we can delete the value
        print("removing ", intf_mac[eth_tll])
        del intf_mac[eth_tll]
#....................................................................................................................#
def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return
        #..............................................#
        # This code is to check weither the MAC address of the device in the list or add it if not.
        hw_addr_dst = packet[0].dst
        hw_addr_src = packet[0].src
        print("dst", packet[0].dst)
        print("src", packet[0].src)
        update_tll(hw_addr_src) 
        if input_port not in intf_mac.keys():
            check_dict_size()
            intf_mac[input_port] = [EthAddr(hw_addr_src),255]
        #..............................................#
        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        ''' if the destination mac address is one of my interface addresses'''
        if hw_addr_dst in mymacs:
            print ("Packet intended for me") 
        else:
            #..............................................#
            # This code is to check if the MAC in the list and find the device connected to and send it to that link. (to match the MAC with the device)
            if isInMap(hw_addr_dst):
                for intf, tup in intf_mac.items(): 
                    print(tup[0])         
                    if tup[0]==hw_addr_dst:
                        print("packet sent")
                        net.send_packet(intf, packet)
            #..............................................#
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:              
                        log_debug("my net interfaces name{}".format(intf.name))
                        log_debug("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
#....................................................................................................................# 