# Wael Aldroubi #
# 300456658 #

#........................................................................#

''' 
    Application Layer of protocol stack.
    Generates data to be sent to other nodes.
'''
import random
import time
from enum import IntEnum

from switchyard.lib.userlib import *

class Ipv():
    ipv4 = 0
    ipv6 = 1
    both = 3

class DataApplication():
    words = "books/pride.txt"
    new_data_wait = 8

    def __init__(self, neighbors, ip_version = Ipv.both):
        self.ip_version = ip_version

        # select IP version(s) to generate traffic for
        if self.ip_version == Ipv.ipv4:
            self.neighbors = neighbors["ipv4"]
        elif self.ip_version == Ipv.ipv6:
            self.neighbors = neighbors["ipv6"]
        else:  # self.ip_version == ipv.both:
            self.neighbors = []
            self.neighbors.extend(neighbors["ipv4"])
            self.neighbors.extend(neighbors["ipv6"])

        self.next_message_time = time.time() + 2  # initial wait is 2s

    def setstack(self, transport):
        self.transport = transport

    def accept_data(self, data):
        # log_debug("Application received {}B of data".format(len(data)))
        print("Application received {}B of data!".format(len(data)))

    def next_send_time(self):
        return random.uniform(self.new_data_wait, self.new_data_wait*2)

    def run(self):
        if time.time() > self.next_message_time:
            self.next_message_time = time.time() + self.next_send_time()
            message = random_data(DataApplication.words)
            destination_host = random.choice(self.neighbors)
            print("Application generated {}B of data for {}".format(len(message), destination_host))
            self.transport.send_packet(destination=destination_host, packet_data=message)

def random_data(file):
    with open(file) as f: lines = random.sample(f.readlines(), 3)
    return " ".join(map(str.strip, lines))
