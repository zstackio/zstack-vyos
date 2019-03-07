#!/bin/bash
err_exit() {
    if [ $? -ne 0 ]; then
        echo $1
        exit 1
    fi
}

tar xzf data.tar.gz
err_exit "unable to untar data.tar.gz"
set -u
TARGET_BIN=/sbin/zvrboot
cp -f zvrboot $TARGET_BIN
chmod +x $TARGET_BIN

VYATTA_BIN=/opt/vyatta/sbin/
cp -f zvrboot $VYATTA_BIN
chmod +x $VYATTA_BIN

mkdir -p /home/vyos/zvr
chown vyos:users /home/vyos/zvr
grep -E 'zvrboot.*zvrboot.log' /opt/vyatta/etc/config/scripts/vyatta-postconfig-bootup.script || echo "/sbin/zvrboot >/home/vyos/zvr/zvrboot.log 2>&1 < /dev/null" >> /opt/vyatta/etc/config/scripts/vyatta-postconfig-bootup.script

exit 0
