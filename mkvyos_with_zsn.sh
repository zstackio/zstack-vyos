#!/bin/bash

export LIBGUESTFS_BACKEND=direct

which guestfish > /dev/null
if [ $? -ne 0 ]; then
   echo "guestfish is not installed"
   exit 1
fi

which qemu-img > /dev/null
if [ $? -ne 0 ]; then
   echo "qemu-img is not installed"
   exit 1
fi

usage() {
   echo "
USAGE:
$0 path_to_image path_to_zvr_tar path_to_zsn_vyos_bin vyos_version"
}

if [ -z $1 ]; then
   echo "missing parameter path_to_image"
   usage
   exit 1
fi

if [ ! -f $1 ]; then
   echo "cannot find the image"
   exit 1
fi

if [ -z $2 ]; then
   echo "missing parameter path_to_zvr_tar"
   usage
   exit 1
fi

if [ ! -f $2 ]; then
   echo "cannot find the zvr.tar.gz"
   exit 1
fi

if [ -z $3 ]; then
   echo "missing parameter path_to_zsn_vyos_bin"
   usage
   exit 1
fi

if [ ! -f $3 ]; then
   echo "cannot find the zsn-agent.bin"
   exit 1
fi

vyosVersion="1.1.7"
if [ ! -z $4 ]; then
   vyosVersion=$4
   echo "vyos version $vyosVersion"
   if [ $vyosVersion != "1.1.7" ] && [ $vyosVersion != "1.2.0" ]; then
       echo "vyos version must be 1.1.7 or 1.2.0"
       usage
       exit 1
   fi
fi

imgfile=$1
isVmdk=0
if echo $1 | grep -q -i '\.vmdk$'; then
    isVmdk=1
    imgfile=${1%%.vmdk}.qcow2
    qemu-img convert -f vmdk -O qcow2 "$1" "$imgfile"
fi

set -e

if [ $vyosVersion = "1.1.7" ]; then
  ROOTPATH="/"
  VyosPostScript="/opt/vyatta/etc/config/scripts/vyatta-postconfig-bootup.script"
else
  ROOTPATH="/boot/zs_vyos/rw/"
  VyosPostScript="/boot/zs_vyos/rw/config/scripts/vyos-postconfig-bootup.script"
fi

tmpdir=$(mktemp -d)

atexit() {
    /bin/rm -fr $tmpdir
    [ $isVmdk -eq 1 ] && /bin/rm -f $imgfile || true
}

trap atexit EXIT SIGHUP SIGINT SIGTERM

tar xzf $2 -C $tmpdir
ZVR=$tmpdir/zvr
ZVRBOOT=$tmpdir/zvrboot
ZVRSCRIPT=$tmpdir/zstack-virtualrouteragent
HAPROXY=$tmpdir/haproxy
GOBETWEEN=$tmpdir/gobetween
KEEPALIVED=$tmpdir/keepalived
PIMD=$tmpdir/pimd
UACCTD=$tmpdir/uacctd
HEALTHCHECK=$tmpdir/healthcheck.sh
SSHD=$tmpdir/sshd.sh
SYSCTL=$tmpdir/sysctl.conf
ZSN=$tmpdir/zsn-crontab.sh
SBIN_DIR=/opt/vyatta/sbin
VERSION=`date +%Y%m%d`
ZVR_VERSION=$tmpdir/version

bash -c "$3"
ZSN_DIR=/usr/local/zstack/zsn-agent/bin
cp $ZSN_DIR/zsn-agent $tmpdir/zsn-agent
cp $ZSN_DIR/zstack-network-agent $tmpdir/zstack-network-agent

guestfish <<_EOF_
add $imgfile
run
mount /dev/sda1 /
write $ROOTPATH/etc/version $VERSION
mkdir-p $ROOTPATH/usr/local/zstack/zsn-agent/bin
upload $ZVR $ROOTPATH$SBIN_DIR/zvr
upload $ZVRBOOT $ROOTPATH$SBIN_DIR/zvrboot
upload $ZVRSCRIPT $ROOTPATH/etc/init.d/zstack-virtualrouteragent
upload $tmpdir/zsn-agent $ROOTPATH$ZSN_DIR/zsn-agent
upload $tmpdir/zstack-network-agent $ROOTPATH/etc/init.d/zstack-network-agent
upload $HAPROXY $ROOTPATH$SBIN_DIR/haproxy
upload $GOBETWEEN $ROOTPATH$SBIN_DIR/gobetween
upload $KEEPALIVED $ROOTPATH/usr/sbin/keepalived
mkdir-p $ROOTPATH/home/vyos/zvr/keepalived/script
upload $PIMD $ROOTPATH/$SBIN_DIR/pimd
upload $UACCTD $ROOTPATH$SBIN_DIR/uacctd
upload $ZVR_VERSION $ROOTPATH/home/vyos/zvr/version
upload $HEALTHCHECK $ROOTPATH/usr/share/healthcheck.sh
mkdir-p $ROOTPATH/home/vyos/zvr/ssh
upload $SSHD $ROOTPATH/home/vyos/zvr/ssh/sshd.sh
upload $SYSCTL $ROOTPATH/etc/sysctl.conf
upload $ZSN $ROOTPATH/usr/local/zstack/zsn-agent/bin/zsn-crontab.sh
mkdir-p $ROOTPATH/opt/vyatta/etc/config/scripts/
upload -<<END $VyosPostScript
#!/bin/bash
chmod +x $SBIN_DIR/zvrboot
chmod +x $SBIN_DIR/zvr
chmod +x /etc/init.d/zstack-virtualrouteragent
chmod +x $ZSN_DIR/zsn-agent
chmod +x /etc/init.d/zstack-network-agent
chmod +x $SBIN_DIR/haproxy
chmod +x $SBIN_DIR/gobetween
chmod +x /usr/sbin/keepalived
chmod +x $SBIN_DIR/pimd
chmod +x $SBIN_DIR/uacctd
chmod +x /usr/share/healthcheck.sh
chmod +x /home/vyos/zvr/ssh/sshd.sh
chmod 644 /etc/sysctl.conf
chmod +x /usr/local/zstack/zsn-agent/bin/zsn-crontab.sh
mkdir -p /home/vyos/zvr
mkdir -p /home/vyos/zvr/keepalived/script
chown vyos:users /home/vyos/ -R
chown vyos:users $SBIN_DIR/zvr
chown vyos:users $ZSN_DIR/zsn-agent
chown vyos:users $SBIN_DIR/haproxy
chown vyos:users $SBIN_DIR/gobetween
chown vyos:users $SBIN_DIR/pimd
chown vyos:users $SBIN_DIR/uacctd
chown vyos:users /usr/share/healthcheck.sh
chown vyos:users /home/vyos/zvr/ssh/sshd.sh
chown root:root /etc/sysctl.conf
chown vyos:users /usr/local/zstack/zsn-agent/bin/zsn-crontab.sh
$SBIN_DIR/zvrboot >/home/vyos/zvr/zvrboot.log 2>&1 < /dev/null &
# disable distributed routing by default
export ZSNP_TMOUT=-960
/etc/init.d/zstack-network-agent start
exit 0
END
download /boot/grub/grub.cfg /tmp/grub.cfg
! sed -e 's/^set[[:space:]]\+timeout[[:space:]]*=[[:space:]]*[[:digit:]]\+/set timeout=0/g' -e '/^echo.*Grub menu/,/^fi$/d' /tmp/grub.cfg > /tmp/grub.cfg.new
upload /tmp/grub.cfg.new /boot/grub/grub.cfg
download $ROOTPATH/etc/security/limits.conf /tmp/limits.conf
! grep -w "vyos" /tmp/limits.conf | grep nofile | grep soft && sed -i 's/vyos soft nofile [0-9]*/vyos soft nofile 20971520/' /tmp/limits.conf || echo "vyos soft nofile 20971520" >> /tmp/limits.conf
! grep -w "vyos" /tmp/limits.conf | grep nofile | grep hard && sed -i 's/vyos hard nofile [0-9]*/vyos hard nofile 20971520/' /tmp/limits.conf || echo "vyos hard nofile 20971520" >> /tmp/limits.conf
! grep -w "root" /tmp/limits.conf | grep nofile | grep soft && sed -i 's/root soft nofile [0-9]*/root soft nofile 20971520/' /tmp/limits.conf || echo "root soft nofile 20971520" >> /tmp/limits.conf
! grep -w "root" /tmp/limits.conf | grep nofile | grep hard && sed -i 's/root hard nofile [0-9]*/root hard nofile 20971520/' /tmp/limits.conf || echo "root hard nofile 20971520" >> /tmp/limits.conf
upload /tmp/limits.conf $ROOTPATH/etc/security/limits.conf
_EOF_

/bin/rm -rf $tmpdir
/bin/rm -rf /tmp/grub.cfg /tmp/limits.conf /tmp/sysctl.conf

if [ $isVmdk -eq 1 ]; then
    /bin/rm -f "$1"
    qemu-img convert -f qcow2 -O vmdk "$imgfile" "$1"
fi

echo "successfully installed $2,$3 to vyos image $1"
