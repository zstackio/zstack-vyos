#!/bin/bash

# set all,default value
sysctl -p

# set specific nic value
NIC_NAMES=$(ls /sys/class/net)
for nic in $NIC_NAMES; do
  echo 0 > /proc/sys/net/ipv6/conf/$nic/accept_dad
  echo 1 > /proc/sys/net/ipv6/conf/$nic/keep_addr_on_down
done