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
TARGET_BIN=/opt/vyatta/sbin/apvm
cp -f apvm $TARGET_BIN
chmod +x $TARGET_BIN
chown vyos:sudo $TARGET_BIN
cp -f zstack-appliancevm /etc/init.d
chmod +x /etc/init.d/zstack-appliancevm
exit 0
