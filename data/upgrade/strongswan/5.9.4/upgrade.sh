#!/bin/bash

set -ex

id -u vyos > /dev/null 2>&1 && USER="vyos" || USER="zstack"

if [ `grep -c "1.1.7" /opt/vyatta/etc/version` -eq '0' ] && [ `grep -c "1.2" /opt/vyatta/etc/version` -eq '0' ]; then
    exit 0
fi

DATA_PATH="/home/$USER/zvr/data"
SW_594_PATH="${DATA_PATH}/upgrade/strongswan/5.9.4"
CURRENT_ARCH=`uname -m`

case "$1" in
    "-d")
        if [[ x"$CURRENT_ARCH" != x"x86_64" && x"$CURRENT_ARCH" != x"aarch64" ]]; then
            exit 0
        fi

        if [[ $(ipsec version | grep 5.9.4) == "" ]];then
            exit 0
        fi

        ipsec stop 2>/dev/null
        rm -rf /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock 2>/dev/null
        /usr/bin/dpkg -r strongswan-zstack
        ;;
    *)
        if [[ x"$CURRENT_ARCH" == x"x86_64" ]]; then
            /usr/bin/dpkg -i ${SW_594_PATH}/strongswan-zstack_5.9.4-1_amd64.deb
        elif [[ x"$CURRENT_ARCH" == x"aarch64" ]];then
            rm -rf /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock 2>/dev/null
            /usr/bin/dpkg -i ${SW_594_PATH}/strongswan-zstack_5.9.4-1_arm64.deb
        else
            exit 0
        fi

        cp ${SW_594_PATH}/ipsec.conf /usr/local/etc/ipsec.conf
        cp ${SW_594_PATH}/ipsec.secrets /usr/local/etc/ipsec.secrets
        cp ${SW_594_PATH}/strongswan.conf /usr/local/etc/strongswan.conf

        if [[ x"$CURRENT_ARCH" == x"x86_64" ]]; then
            libcrypto_file=/usr/lib/libcrypto.so.1.0.0
            if [[ -L "$libcrypto_file" ]]; then
                rm -rf $libcrypto_file 2>/dev/null
            fi
            ln -s /usr/local/lib/libcrypto.so.1.0.0 $libcrypto_file
        fi
        ;;
esac

exit 0
