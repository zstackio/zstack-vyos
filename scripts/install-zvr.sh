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
TARGET_BIN=/opt/vyatta/sbin/zvr
cp -f zvr $TARGET_BIN
chmod +x $TARGET_BIN
chown vyos:users $TARGET_BIN
cp -f zstack-virtualrouteragent /etc/init.d
chmod +x /etc/init.d/zstack-virtualrouteragent

TARGET_HAPROXY=/opt/vyatta/sbin/haproxy
diff haproxy $TARGET_HAPROXY
if [ $? -ne 0 ]; then
    yes | cp haproxy $TARGET_HAPROXY
fi
chown vyos:users $TARGET_HAPROXY
chmod +x $TARGET_HAPROXY

exit 0
