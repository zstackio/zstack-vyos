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
LABLE=''
[ x"$ARCH" != x"x86_64" ] && LABLE="_$ARCH"

TARGET_BIN=/opt/vyatta/sbin/zvr
cp -f zvr${LABLE} $TARGET_BIN
chmod +x $TARGET_BIN
chown vyos:users $TARGET_BIN
cp -f zstack-virtualrouteragent /etc/init.d
chmod +x /etc/init.d/zstack-virtualrouteragent

TARGET_HAPROXY=/opt/vyatta/sbin/haproxy
diff haproxy${LABLE} $TARGET_HAPROXY
if [ $? -ne 0 ]; then
    yes | cp -f haproxy${LABLE} $TARGET_HAPROXY
fi
chown vyos:users $TARGET_HAPROXY
chmod +x $TARGET_HAPROXY

TARGET_GOBETWEEN=/opt/vyatta/sbin/gobetween
diff gobetween${LABLE} $TARGET_GOBETWEEN
if [ $? -ne 0 ]; then
    yes | cp -f gobetween${LABLE} $TARGET_GOBETWEEN
    yes | cp -f healthcheck.sh /usr/share/
fi
chown vyos:users $TARGET_GOBETWEEN
chmod +x $TARGET_GOBETWEEN
chown vyos:users /usr/share/healthcheck.sh
chmod +x /usr/share/healthcheck.sh

TARGET_KEEPALIVED=/usr/sbin/keepalived
diff keepalived${LABLE} $TARGET_KEEPALIVED
if [ $? -ne 0 ]; then
    yes | cp -f keepalived${LABLE} $TARGET_KEEPALIVED
    yes | mkdir -p /home/vyos/zvr/keepalived/script/
fi
chown vyos:users $TARGET_KEEPALIVED
chmod +x $TARGET_KEEPALIVED

TARGET_PIMD=/opt/vyatta/sbin/pimd
if [[ ! -f $TARGET_PIMD || $(diff pimd${LABLE} $TARGET_PIMD) ]]; then
    yes | cp -f pimd${LABLE} $TARGET_PIMD
fi
chown vyos:users $TARGET_PIMD
chmod +x $TARGET_PIMD

TARGET_SSHD=/home/vyos/zvr/ssh/sshd.sh
if [[ ! -f $TARGET_SSHD || $(diff sshd.sh $TARGET_SSHD) ]]; then
    yes | mkdir -p `dirname $TARGET_SSHD`
    yes | cp -f sshd.sh $TARGET_SSHD
fi
chown vyos:users $TARGET_SSHD
chmod +x $TARGET_SSHD

TARGET_ZVRMONITOR=/home/vyos/zvr/ssh/zvr-monitor.sh
if [[ ! -f $TARGET_ZVRMONITOR || $(diff zvr-monitor.sh $TARGET_ZVRMONITOR) ]]; then
    yes | mkdir -p `dirname $TARGET_ZVRMONITOR`
    yes | cp -f zvr-monitor.sh $TARGET_ZVRMONITOR
fi
chown vyos:users $TARGET_ZVRMONITOR
chmod +x $TARGET_ZVRMONITOR

TARGET_ZVRREBOOT=/home/vyos/zvr/ssh/zvr-reboot.sh
if [[ ! -f $TARGET_ZVRREBOOT || $(diff zvr-reboot.sh $TARGET_ZVRREBOOT) ]]; then
    yes | mkdir -p `dirname $TARGET_ZVRREBOOT`
    yes | cp -f zvr-reboot.sh $TARGET_ZVRREBOOT
fi
chown vyos:users $TARGET_ZVRREBOOT
chmod +x $TARGET_ZVRREBOOT

TARGET_CPUMONITOR=/etc/logrotate.d/cpu-monitor
if [[ ! -f $TARGET_CPUMONITOR || $(diff cpu-monitor $TARGET_CPUMONITOR) ]]; then
    yes | mkdir -p `dirname $TARGET_CPUMONITOR`
    yes | cp -f cpu-monitor $TARGET_CPUMONITOR
fi

TARGET_ZSN=/usr/local/zstack/zsn-agent/bin/zsn-crontab.sh
if [[ ! -f $TARGET_ZSN || $(diff zsn-crontab.sh $TARGET_ZSN) ]]; then
    yes | mkdir -p `dirname $TARGET_ZSN`
    yes | cp -f zsn-crontab.sh $TARGET_ZSN
fi
chown vyos:users $TARGET_ZSN
chmod +x $TARGET_ZSN

TARGET_UAACTD=/opt/vyatta/sbin/uacctd
if [[ ! -f $TARGET_UAACTD || $(diff uacctd $TARGET_UAACTD) ]]; then
    yes | cp -f uacctd $TARGET_UAACTD
fi
chown vyos:users $TARGET_UAACTD
chmod +x $TARGET_UAACTD

TARGET_GOPRLIMIT=/opt/vyatta/sbin/goprlimit
diff goprlimit $TARGET_GOPRLIMIT
if [ $? -ne 0 ]; then
    yes | cp -f goprlimit $TARGET_GOPRLIMIT
fi

TARGET_SYSCONF=/etc/sysctl.conf
sudo cp -f sysctl.conf $TARGET_SYSCONF
sudo chmod 644 $TARGET_SYSCONF
sudo chown root:root $TARGET_SYSCONF

TARGET_CONNTRACKD_CONF=/etc/conntrackd/conntrackd.conf
sudo cp -f conntrackd.conf $TARGET_CONNTRACKD_CONF
sudo chmod 644 $TARGET_CONNTRACKD_CONF
sudo chown root:root $TARGET_CONNTRACKD_CONF

dpkg -l dnsmasq
if [ $? -ne 0 -a x"$ARCH" = x"aarch64" ];then
    rm -rf /etc/dnsmasq.conf
    sudo dpkg -i dnsmasq_pkg/*
fi

TAGET_TEMP_SCRIPT=/home/vyos/zvr/keepalived/temp/ipsec.sh
if [[ ! -f $TAGET_TEMP_SCRIPT || $(diff ipsec.sh $TAGET_TEMP_SCRIPT) ]]; then
    yes | mkdir -p `dirname $TAGET_TEMP_SCRIPT`
    yes | cp -f ipsec.sh $TAGET_TEMP_SCRIPT
fi
chown vyos:users $TAGET_TEMP_SCRIPT
chmod +x $TAGET_TEMP_SCRIPT

exit 0
