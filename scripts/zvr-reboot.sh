#!/bin/bash

HOMDIR=/home/vyos/zvr
LOGFILE=$HOMDIR/zvrReboot.log
BOOTSTRAPINFO=$HOMDIR/bootstrap-info.json

parse_json(){
  echo "${1//\"/}" | sed "s/.*$2:\([^,}]*\).*/\1/"
}

restart_zvr() {
  sudo bash /etc/init.d/zstack-virtualrouteragent restart >> /tmp/agentRestart.log 2>&1
}

manageNicIp=$(grep -A 5 "managementNic" $BOOTSTRAPINFO | grep "ip" | awk '{print $2}')
if [ x$manageNicIp = x"" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') get managementNic ip failed, restart zstack virtual router " >> $LOGFILE
    restart_zvr
    exit
fi

manageNicIp=$(echo $manageNicIp | sed -e s/,// | sed -e s/\"//g)
if [ x$manageNicIp = x"" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') get managementNic ip failed, restart zstack virtual router " >> $LOGFILE
    restart_zvr
    exit
fi

zvr_version=$(cat $HOMDIR/version)
if [ x$zvr_version = x"" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') get zvr version failed, restart zstack virtual router " >> $LOGFILE
    restart_zvr
    exit
fi

##check zvr versoin
uri=http://$manageNicIp:7272/test
pid=$(ps aux | grep '/opt/vyatta/sbin/zvr' | grep -v grep | awk '{print $2}')
if [ x$pid = x"" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') zstack virtual router is stopped, restart zstack virtual router" >> $LOGFILE
    restart_zvr
else
    ret=$(timeout 5 curl -sb -H "Content-Type: application/json; charset=utf-8" -H "User-Agent: curl" -X POST $uri)
    if [[ "$ret" =~ "\"success\":true" ]]; then
        current_version=$(parse_json $ret "zvrVersion")
        if [ x$zvr_version != x$current_version ];then
            echo "$(date '+%Y-%m-%d %H:%M:%S') the running zvr version is $current_version and management node zvr version is $zvr_version, restart zstack virtual router" >> $LOGFILE
            restart_zvr
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') the running zvr version is $current_version and management node zvr version is $zvr_version, no need restart zstack virtual router" >> $LOGFILE
        fi
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') zstack virtual router pid: $pid, curl  $uri failed, $ret".restart zstack virtual router>> $LOGFILE
        restart_zvr
    fi
fi
