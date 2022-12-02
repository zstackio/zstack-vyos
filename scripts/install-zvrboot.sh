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

ARCH=`uname -m`
SUFFIX="_$ARCH"

id -u vyos > /dev/null 2>&1 && USER="vyos" || USER="zstack"

TARGET_BIN=/sbin/zvrboot
cp -f zvrboot${SUFFIX} $TARGET_BIN
chmod +x $TARGET_BIN


[ x"$USER" == x"vyos" ] && ZVR_ROOT_PATH="/opt/vyatta/sbin/zvrboot" || ZVR_ROOT_PATH="/usr/local/bin/zvrboot"
cp -f zvrboot${SUFFIX} $ZVR_ROOT_PATH
chmod +x $ZVR_ROOT_PATH

mkdir -p /home/$USER/zvr
chown $USER:users /home/$USER/zvr

if [ x"$USER" == x"vyos" ];then
    grep -E 'zvrboot.*zvrboot.log' /opt/vyatta/etc/config/scripts/vyatta-postconfig-bootup.script \
        || echo "/sbin/zvrboot >/home/vyos/zvr/zvrboot.log 2>&1 < /dev/null" \
            >> /opt/vyatta/etc/config/scripts/vyatta-postconfig-bootup.script
fi

exit 0
