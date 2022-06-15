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

DATA=$tmpdir/zvr-data.tar.gz
BOOTSCRIPT=$tmpdir/vyos-postconfig-bootup.script
VERSION=`date +%Y%m%d`

bash -c "$3"
ZSN_DIR=/usr/local/zstack/zsn-agent/bin
cp $ZSN_DIR/zsn-agent $tmpdir/zsn-agent
cp $ZSN_DIR/zstack-network-agent $tmpdir/zstack-network-agent

guestfish <<_EOF_
add $imgfile
run
mount /dev/sda1 /
write $ROOTPATH/etc/version $VERSION

mkdir-p $ROOTPATH/home/vyos/zvr/data/
mkdir-p $ROOTPATH/home/vyos/zvr/keepalived/script
mkdir-p $ROOTPATH/home/vyos/zvr/ssh
mkdir-p $ROOTPATH/etc/conntrackd
mkdir-p $ROOTPATH/opt/vyatta/etc/config/scripts/
mkdir-p $ROOTPATH/usr/local/zstack/zsn-agent/bin

upload $tmpdir/zsn-agent $ROOTPATH$ZSN_DIR/zsn-agent
upload $tmpdir/zstack-network-agent $ROOTPATH/etc/init.d/zstack-network-agent
upload $BOOTSCRIPT $VyosPostScript
tar-in $DATA $ROOTPATH/home/vyos/zvr/data/ compress:gzip

download /boot/grub/grub.cfg /tmp/grub.cfg
! sed -e 's/^set[[:space:]]\+timeout[[:space:]]*=[[:space:]]*[[:digit:]]\+/set timeout=0/g' -e '/^echo.*Grub menu/,/^fi$/d' /tmp/grub.cfg > /tmp/grub.cfg.new
upload /tmp/grub.cfg.new /boot/grub/grub.cfg
download $ROOTPATH/etc/security/limits.conf /tmp/limits.conf
! grep -w "vyos" /tmp/limits.conf | grep nofile | grep soft && sed -i 's/vyos soft nofile [0-9]*/vyos soft nofile 20971520/' /tmp/limits.conf || echo "vyos soft nofile 20971520" >> /tmp/limits.conf
! grep -w "vyos" /tmp/limits.conf | grep nofile | grep hard && sed -i 's/vyos hard nofile [0-9]*/vyos hard nofile 20971520/' /tmp/limits.conf || echo "vyos hard nofile 20971520" >> /tmp/limits.conf
#! grep -w "root" /tmp/limits.conf | grep nofile | grep soft && sed -i 's/root soft nofile [0-9]*/root soft nofile 20971520/' /tmp/limits.conf || echo "root soft nofile 20971520" >> /tmp/limits.conf
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
