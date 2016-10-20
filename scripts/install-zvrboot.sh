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

mkdir -p /home/vyos/zvr
chown vyos:users /home/vyos/zvr
echo "/sbin/zvrboot >/home/vyos/zvr/zvrboot.log 2>&1 < /dev/null" > /opt/vyatta/etc/config/scripts/vyatta-postconfig-bootup.script

exit 0
