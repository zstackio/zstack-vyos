#!/bin/bash

export LIBGUESTFS_BACKEND=direct

which guestfish > /dev/null
if [ $? -ne 0 ]; then
   echo "guestfish is not installed"
   exit 1
fi

usage() {
   echo "
USAGE:
$0 path_to_image path_to_zvr_tar"
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

set -e
tmpdir=$(mktemp -d)

function atexit() {
   rm -rf $tmpdir
}
trap atexit EXIT SIGHUP SIGINT SIGTERM

tar xzf $2 -C $tmpdir
ZVR=$tmpdir/zvr
ZVRBOOT=$tmpdir/zvrboot
ZVRSCRIPT=$tmpdir/zstack-virtualrouteragent

guestfish <<_EOF_
add $1
run
mount /dev/sda1 /
upload $ZVR /opt/vyatta/sbin/zvr
upload $ZVRBOOT /sbin/zvrboot
upload $ZVRSCRIPT /etc/init.d/zstack-virtualrouteragent
upload -<<END /opt/vyatta/etc/config/scripts/vyatta-postconfig-bootup.script
#!/bin/bash
chmod +x /sbin/zvrboot
chmod +x /opt/vyatta/sbin/zvr
chmod +x /etc/init.d/zstack-virtualrouteragent
mkdir -p /home/vyos/zvr
chown vyos:users /home/vyos/zvr
chown vyos:users /opt/vyatta/sbin/zvr
/sbin/zvrboot >/home/vyos/zvr/zvrboot.log 2>&1 < /dev/null
END
_EOF_

rm -rf $tmpdir
echo "successfully installed $2 to vyos image $1"
