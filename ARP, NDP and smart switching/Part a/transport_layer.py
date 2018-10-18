# Wael Aldroubi #
# 300456658 #

#........................................................................#

#!/usr/bin/env python3

'''
    Python implementation of the stopandwait.c by David C. Harrison (davidh@ecs.vuw.ac.nz) 
    September 2014. stopandwait.c is a modification of a cnet v3.2.4's "stop-and-wait link 
    protocol" based on Tanenbaum's `protocol 4', 2nd edition, p227 (or his 3rd edition, p205).
    
    Tanenbaum's protocol "employs only data and acknowledgement frames - piggybacking 
    and negative acknowledgements are not used."
    
    David's modification added support for more than two hosts and simultaneous 
    send/receive of data.

    This version simplifies the sequence number strategy and removes address field to make
    it ip version independent.
'''

from enum import IntEnum 
from ipaddress import IPv6Address
from sys import byteorder
import threading
import time
import struct
import random

from switchyard.lib.userlib import *

# for printing debug output from only this layer
# def log_debug(to_print):
#     print(to_print)

class StopAndWaitType(IntEnum):
    Data = 0
    Ack = 1

class StopAndWaitHeader(PacketHeaderBase):
    ''' Basic header class for the stopandwait protocol '''
    _PACKFMT = '!HHHH'
    _MINLEN = struct.calcsize(_PACKFMT)

    def __init__(self, msg_type=None, seq=None, **kwargs):
        self.msg_type = msg_type
        self.seq = seq

        self._payload = b''
        PacketHeaderBase.__init__(self, **kwargs)

    def to_bytes(self):
        l = len(self.payload)
        header = struct.pack(StopAndWaitHeader._PACKFMT, 
            self.msg_type, len(self.payload), 0, self.seq)
        chksum = checksum(header+self.payload)
        return struct.pack(StopAndWaitHeader._PACKFMT, 
            self.msg_type, len(self.payload), chksum, self.seq) + self.payload

    def from_bytes(self, raw):
        if len(raw) < StopAndWaitHeader._MINLEN:
            return 0
        fields = struct.unpack(StopAndWaitHeader._PACKFMT, raw[:StopAndWaitHeader._MINLEN])
        self.msg_type = fields[0]
        length = fields[1]
        self.checksum = fields[2]

        chksum = checksum(raw, skip_word=2)
        if self.checksum != chksum:
            log_debug("BAD CHECKSUM")

        self.seq = fields[3]
        self._payload = raw[StopAndWaitHeader._MINLEN:StopAndWaitHeader._MINLEN+length]
        return StopAndWaitHeader._MINLEN + length

    @property
    def payload(self):
        return self._payload

    @payload.setter
    def payload(self, value):
        if type(value) is type(str()):
            self._payload = value.encode()
        else:
            self._payload = value

    def __len__(self):
        return len(self.payload)

    def __str__(self):
        return 'stop and wait message type:{} {}B payload'.format(
            self.msg_type.__class__.__name__, len(self.payload) )

class StopAndWait():
    ''' 
        Modified StopAndWait transport protocol. A semi-reliable transfer protocol.
        Buffers application data, and manages message sending and acknowledgements.
    '''
    ack_timeout_time = 2  # one second
    queue_limit = 20

    def __init__(self, inet6, inet4):
        threading.Thread.__init__(self)
        self.inet6 = IPv6Address(inet6)
        self.inet4 = IPv4Address(inet4)

        self.ip = None
        self.app = None

        self.send_queue = []  # (pkt, dst, seq, timeout_time)
        #self.current_seq = 0
        self.current_seq = random.randint(0,0xffff)


        self.waiting_on_ack = False

    def setstack(self, ip=None, app=None):
        ''' Attach the layer above and below '''
        self.ip = ip
        self.app = app

    def run(self):
        ''' Check the ACK timeouts and send delayed packets '''
        assert self.ip != None
        assert self.app != None

        if len(self.send_queue) <= 0:
            return

        front_of_queue = self.send_queue[0]

        # check timeout
        if self.waiting_on_ack:
            if time.time() >= front_of_queue["timeout"]:
                log_debug( "DATA message ACK timed out, resending seq: {} to: {}".format(front_of_queue["seq"],front_of_queue["dst"]) )
                front_of_queue["timeout"] = time.time() + StopAndWait.ack_timeout_time
                self.ip.send_packet(front_of_queue["pkt"], front_of_queue["dst"])
            # else: do nothing
        else:
            if front_of_queue["timeout"] == None:
                # send the next packet in the queue
                front_of_queue["timeout"] = time.time() + StopAndWait.ack_timeout_time
                self.waiting_on_ack = True
                self.ip.send_packet(front_of_queue["pkt"], front_of_queue["dst"])
            else:
                log_debug("This shouldn't happen..")

    def get_src_address(self, dst_address):
        ''' Returns the correct version of IP address given the sender's IP address '''
        if type(dst_address) == type(IPv6Address("0::0")):
            return self.inet6
        else:
            return self.inet4

    def send_packet(self, packet_data, destination):
        ''' Receives data from above and prepares it for sending to lower layer '''

        if len(self.send_queue) <= StopAndWait.queue_limit:
            # Create SAW packet and add to send queue
            packet = StopAndWaitHeader(msg_type=StopAndWaitType.Data, seq=self.current_seq)
            packet.payload = packet_data

            if not self.waiting_on_ack:
                self.waiting_on_ack = True

                self.send_queue.append( {"pkt":packet, "dst":destination, "seq":self.current_seq, 
                    "timeout":time.time() + StopAndWait.ack_timeout_time} )
                self.ip.send_packet(packet, destination)
                
                log_debug( "DATA message sent to: {}".format(destination, packet.seq) )
            else:
                self.send_queue.append( {"pkt":packet, "dst":destination, "seq":self.current_seq, "timeout":None} )

            self.current_seq += 1
        else:
            log_debug("Send queue is full, message dropped")

    def handle_ack(self, packet, src_address):
        ''' Handle the receipt of a ACK type message '''
        to_print = "ACK received from: {} seq: {}".format(
            src_address, packet.seq)

        if len(self.send_queue) <= 0:
            log_debug("{} (ignored - no message waiting for ACK)".format(to_print))
            return

        front_of_queue = self.send_queue[0]
        if src_address != front_of_queue["dst"]:
            return log_debug("{} (ignored - ACK from incorrect host".format(to_print))
        if packet.seq < front_of_queue["seq"]:
            return log_debug("{} (ignored - seq already acknowledged".format(to_print))
                
        # unblock sending queue, allowing next message to be sent
        self.send_queue.pop()
        self.waiting_on_ack = False
        log_debug(to_print)

    def handle_data(self, packet, src_address):
        ''' Handle the receipt of a data type message '''
        to_print = "DATA received from: {} seq: {}  (Message received {}B)".format(
            src_address, packet.seq, len(packet))

        to_print = "Ack to {})".format(self.get_src_address(dst_address=src_address))
        self.app.accept_data(packet.payload)
        
        ack = StopAndWaitHeader(msg_type=StopAndWaitType.Ack, seq=packet.seq)

        self.ip.send_packet(ack, src_address)
        log_debug( "ACK message sent to: {} seq: {}".format(src_address, packet.seq) )

    def accept_packet(self, packet_data, src_address):
        ''' Accept and process packet from lower layer '''
        packet = StopAndWaitHeader()
        packet.from_bytes(raw=packet_data.to_bytes())

        if packet.msg_type == StopAndWaitType.Ack:
            self.handle_ack(packet, src_address)
        elif packet.msg_type == StopAndWaitType.Data:
            self.handle_data(packet, src_address)
        else:
            log_debug("Received unrecognised message (ignored)")

    def __str__(self):
        return "Stop and wait object"
