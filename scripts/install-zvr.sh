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
    yes | cp -f haproxy $TARGET_HAPROXY
fi
chown vyos:users $TARGET_HAPROXY
chmod +x $TARGET_HAPROXY

TARGET_GOBETWEEN=/opt/vyatta/sbin/gobetween
diff gobetween $TARGET_GOBETWEEN
if [ $? -ne 0 ]; then
    yes | cp -f gobetween $TARGET_GOBETWEEN
    yes | cp -f healthcheck.sh /usr/share/
fi
chown vyos:users $TARGET_GOBETWEEN
chmod +x $TARGET_GOBETWEEN
chown vyos:users /usr/share/healthcheck.sh
chmod +x /usr/share/healthcheck.sh

exit 0
