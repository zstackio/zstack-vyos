#!/bin/sh
# remove it as healthcheck.sh and put it the location you want

if [ $# -ne 2 ];then
  echo "Usage: $0 <ip address> <port>"
  exit 1
fi

line=`ping $1 -c 1 -s 1 -W 1| egrep "100% packet loss"| wc -l`

if [ "$line" != "0"  ];then
  #echo "$1 no response, please check the host & firewall rule!"
  echo -n "fail"
  exit 0
fi

ret=`/bin/nc -unvz -w 1 $1 $2 2>&1 | egrep 'open'& > /dev/null`
if [ $? -ne 0 ] || [ "$ret" = "" ]; then
  echo -n "fail"
else
  echo -n "success"
fi
exit 0
