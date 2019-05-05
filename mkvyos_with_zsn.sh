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
$0 path_to_image path_to_zvr_tar path_to_zsn_vyos_bin"
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

imgfile=$1
isVmdk=0
if echo $1 | grep -q -i '\.vmdk$'; then
    isVmdk=1
    imgfile=${1%%.vmdk}.qcow2
    qemu-img convert -f vmdk -O qcow2 "$1" "$imgfile"
fi

set -e

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
PIMD=$tmpdir/pimd
HEALTHCHECK=$tmpdir/healthcheck.sh
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
write /etc/version $VERSION
mkdir-p /usr/local/zstack/zsn-agent/bin
upload $ZVR $SBIN_DIR/zvr
upload $ZVRBOOT $SBIN_DIR/zvrboot
upload $ZVRSCRIPT /etc/init.d/zstack-virtualrouteragent
upload $tmpdir/zsn-agent $ZSN_DIR/zsn-agent
upload $tmpdir/zstack-network-agent /etc/init.d/zstack-network-agent
upload $HAPROXY $SBIN_DIR/haproxy
upload $GOBETWEEN $SBIN_DIR/gobetween
upload $PIMD $SBIN_DIR/pimd
mkdir-p /home/vyos/zvr/
upload $ZVR_VERSION /home/vyos/zvr/version
upload $HEALTHCHECK /usr/share/healthcheck.sh
upload -<<END /opt/vyatta/etc/config/scripts/vyatta-postconfig-bootup.script
#!/bin/bash
chmod +x $SBIN_DIR/zvrboot
chmod +x $SBIN_DIR/zvr
chmod +x /etc/init.d/zstack-virtualrouteragent
chmod +x $ZSN_DIR/zsn-agent
chmod +x /etc/init.d/zstack-network-agent
chmod +x $SBIN_DIR/haproxy
chmod +x $SBIN_DIR/gobetween
chmod +x $SBIN_DIR/pimd
chmod +x /usr/share/healthcheck.sh
mkdir -p /home/vyos/zvr
chown vyos:users /home/vyos/zvr
chown vyos:users $SBIN_DIR/zvr
chown vyos:users $ZSN_DIR/zsn-agent
chown vyos:users $SBIN_DIR/haproxy
chown vyos:users $SBIN_DIR/gobetween
chown vyos:users $SBIN_DIR/pimd
chown vyos:users /usr/share/healthcheck.sh
$SBIN_DIR/zvrboot >/home/vyos/zvr/zvrboot.log 2>&1 < /dev/null &
# disable distributed routing by default
export ZSNP_TMOUT=-960
/etc/init.d/zstack-network-agent start
exit 0
END
download /boot/grub/grub.cfg /tmp/grub.cfg
! sed -e 's/^set[[:space:]]\+timeout[[:space:]]*=[[:space:]]*[[:digit:]]\+/set timeout=0/g' -e '/^echo.*Grub menu/,/^fi$/d' /tmp/grub.cfg > /tmp/grub.cfg.new
upload /tmp/grub.cfg.new /boot/grub/grub.cfg
download /etc/security/limits.conf /tmp/limits.conf
! grep -w "vyos" /tmp/limits.conf  | grep soft || echo "vyos soft nofile 1000000" >> /tmp/limits.conf
! grep -w "vyos" /tmp/limits.conf  | grep hard || echo "vyos hard nofile 1000000" >> /tmp/limits.conf
upload /tmp/limits.conf /etc/security/limits.conf
_EOF_

/bin/rm -rf $tmpdir

if [ $isVmdk -eq 1 ]; then
    /bin/rm -f "$1"
    qemu-img convert -f qcow2 -O vmdk "$imgfile" "$1"
fi

echo "successfully installed $2,$3 to vyos image $1"
