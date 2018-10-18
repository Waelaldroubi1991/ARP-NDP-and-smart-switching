# Wael Aldroubi #
# 300456658 #

#........................................................................#

#!/bin/bash

#
# Script to start mininet and open a terminal for each host
#

if [ -z "$1" ] ; then
   NUM_HOSTS=4
else
   NUM_HOSTS=$1
fi

NUM_SWITCHES=1

# set up switchyard environment to match mininet
sed -i -e 's/\(number_of_hosts = *\)[^ ]*/\1'$NUM_HOSTS'/' \
    -e 's/\(number_of_switches = *\)[^ ]*/\1'$NUM_SWITCHES'/' preferences.py

# start mininet
mn --mac --topo=linear,$NUM_SWITCHES,$NUM_HOSTS

# > xterm h1
# > xterm h2
# etc..