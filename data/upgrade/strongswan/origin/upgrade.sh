#!/bin/bash

case "$1" in
    "-d")
        if [ $(ipsec version | grep 4.5.2) == "" ] || [ $(ipsec version | grep 5.7.2) == "" ];then
            exit 0
        fi

        ipsec stop 2>/dev/null
        mv /usr/sbin/ipsec /usr/sbin/ipsec_bak
        ;;
    *)
        mv /usr/sbin/ipsec_bak /usr/sbin/ipsec
        ;;
esac

exit 0
