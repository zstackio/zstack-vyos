#!/bin/bash

BOOTLOG=/home/vyos/zvr/zvrstartup.log
sudo bash /etc/init.d/zstack-network-agent status
ret=$?
if [ $ret -ne 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') start zstack network agent by vyos cron job" >>$BOOTLOG
    sudo bash /etc/init.d/zstack-network-agent start
fi