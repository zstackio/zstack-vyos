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

check_version() {
    ret=$(timeout 3 curl -sb -H "Content-Type: application/json; charset=utf-8" -H "User-Agent: curl" -X POST $uri)
    if [[ "$ret" =~ "\"success\":true" ]]; then
        current_version=$(parse_json $ret "zvrVersion")
        if [ x$zvr_version != x$current_version ];then
            su - vyos -c "echo $(date '+%Y-%m-%d %H:%M:%S') the running zvr version is $current_version and management node zvr version is $zvr_version >> $LOGFILE"
            result="restart"
        else
            su - vyos -c "echo $(date '+%Y-%m-%d %H:%M:%S') the running zvr version is $current_version and management node zvr version is $zvr_version, no need restart zstack virtual router >> $LOGFILE"
            result="success"
        fi
    elif [[ "$ret" =~ "no plugin registered the path" ]]; then ##old version image, there is no test command in zvr
        result="restart"
    else
        result="failed"
    fi
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
    retry=1
    maxRetries=10
    until [ ${retry} -ge ${maxRetries} ]
    do
        check_version
        if [ x"$result" = x"failed" ]
        then
            echo "failed, retrying the $retry time"
            su - vyos -c "$(date '+%Y-%m-%d %H:%M:%S') zstack virtual router pid: $pid, curl  $uri failed, retrying the $retry time >> $LOGFILE"
            sleep $(( retry++ ))
        else
            ((retry=maxRetries+1))
        fi
    done

    if [ x"$result" = x"restart" ]
    then
        echo "$(date '+%Y-%m-%d %H:%M:%S') running zvr version is different from management node zvr version, restart zstack virtual router" >> $LOGFILE
        restart_zvr
    fi
fi
