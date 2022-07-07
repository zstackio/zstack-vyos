#!/bin/bash

if [ `grep -c "1.1.7" /opt/vyatta/etc/version` -eq '0' ]; then
    exit 0
fi

DATA_PATH="/home/vyos/zvr/data"
SW_594_PATH="${DATA_PATH}/upgrade/strongswan/5.9.4"

case "$1" in
    "-d")
        if [[ $(ipsec version | grep 5.9.4) == "" ]];then
            exit 0
        fi

        ipsec stop 2>/dev/null
        /usr/bin/dpkg -r strongswan-zstack
        ;;
    *)
        /usr/bin/dpkg -i ${SW_594_PATH}/strongswan-zstack_5.9.4-1_amd64.deb
        cp ${SW_594_PATH}/ipsec.conf /usr/local/etc/ipsec.conf
        cp ${SW_594_PATH}/ipsec.secrets /usr/local/etc/ipsec.secrets
        cp ${SW_594_PATH}/strongswan.conf /usr/local/etc/strongswan.conf

        libcrypto_file=/usr/lib/libcrypto.so.1.0.0
        if [[ -L "$libcrypto_file" ]]; then
            rm -rf $libcrypto_file 2>/dev/null
        fi
        ln -s /usr/local/lib/libcrypto.so.1.0.0 $libcrypto_file
        ;;
esac

exit 0
