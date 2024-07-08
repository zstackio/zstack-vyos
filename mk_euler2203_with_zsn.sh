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

DATA=$tmpdir/zvr-data.tar.gz
BOOTSCRIPT=$tmpdir/zstack-vrouter-euler2203-bootup

bash -c "$3"
ZSN_DIR=/usr/local/zstack/zsn-agent/bin
cp $ZSN_DIR/zsn-agent $tmpdir/zsn-agent
cp $ZSN_DIR/zstack-network-agent $tmpdir/zstack-network-agent

guestfish <<_EOF_
add $imgfile
run
mount /dev/openeuler/root /
mkdir-p /usr/local/zstack/zsn-agent/bin
upload $tmpdir/zsn-agent $ZSN_DIR/zsn-agent
upload $tmpdir/zstack-network-agent  /usr/local/bin/zstack-network-agent
chmod 777  /usr/local/bin/zstack-network-agent
upload $BOOTSCRIPT   /usr/local/bin/zstack-vrouter-bootup
chmod 777  /usr/local/bin/zstack-vrouter-bootup

mkdir-p /home/zstack/zvr/data/
tar-in $DATA /home/zstack/zvr/data/ compress:gzip
_EOF_

#/bin/rm -rf $tmpdir

if [ $isVmdk -eq 1 ]; then
    /bin/rm -f "$1"
    qemu-img convert -f qcow2 -O vmdk "$imgfile" "$1"
fi

echo "successfully installed $2,$3 to vyos image $1"
