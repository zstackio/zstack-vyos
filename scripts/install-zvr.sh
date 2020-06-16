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

TARGET_KEEPALIVED=/usr/sbin/keepalived
diff keepalived $TARGET_KEEPALIVED
if [ $? -ne 0 ]; then
    yes | cp -f keepalived $TARGET_KEEPALIVED
    yes | mkdir -p /home/vyos/zvr/keepalived/script/
fi
chown vyos:users $TARGET_KEEPALIVED
chmod +x $TARGET_KEEPALIVED

TARGET_PIMD=/opt/vyatta/sbin/pimd
if [[ ! -f $TARGET_PIMD || $(diff pimd $TARGET_PIMD) ]]; then
    yes | cp -f pimd $TARGET_PIMD
fi
chown vyos:users $TARGET_PIMD
chmod +x $TARGET_PIMD

TARGET_SSHD=/home/vyos/zvr/ssh/sshd.sh
if [[ ! -f $TARGET_SSHD || $(diff sshd.sh $TARGET_SSHD) ]]; then
    yes | mkdir -p /home/vyos/zvr/ssh/
    yes | cp -f sshd.sh $TARGET_SSHD
fi
chown vyos:users $TARGET_SSHD
chmod +x $TARGET_SSHD

TARGET_ZSN=/usr/local/zstack/zsn-agent/bin/zsn-crontab.sh
if [[ ! -f $TARGET_ZSN || $(diff zsn-crontab.sh $TARGET_ZSN) ]]; then
    yes | cp -f zsn-crontab.sh $TARGET_ZSN
fi
chown vyos:users $TARGET_ZSN
chmod +x $TARGET_ZSN

exit 0
