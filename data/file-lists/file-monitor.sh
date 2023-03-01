#!/bin/bash

HOMDIR=/home/vyos/zvr
LOGFILE=$HOMDIR/systemMonitor.log
BOOTSTRAPINFO=$HOMDIR/bootstrap-info.json
DEFAULT_DIR="bin boot config dev etc home install.log lib lib64 lost+found media mnt opt proc root sbin srv sys tmp usr var"
DEFAULT_MONIOTOR_DIR="/home /root /tmp /usr /var /opt /etc"
MAX_NUM_OF_MONITOR_DIR=10
template='{"filePath":"var1","fileSize":"var2"}'
ret_template='{"applianceVmUuid":"var1", "abnormalFiles":[var2], "diskTotal":"var3","diskUsed":"var4","diskUsedutilization":"var5"}'
ret=""
NEED_REPORT_MN="false"
sizeFilesMap=""
retJson=""

managementNodeIp=$(grep "managementNodeIp" $BOOTSTRAPINFO | awk '{print $2}')
if [ x$managementNodeIp = x"" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') get managementNodeIp failed " >> $LOGFILE
    exit
fi

managementNodeIp=$(echo $managementNodeIp | sed -e s/,// | sed -e s/\"//g)
if [ x$managementNodeIp = x"" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') get managementNodeIp failed " >> $LOGFILE
    exit
fi

applianceVmUuid=$(grep "uuid" $BOOTSTRAPINFO |awk '{print $2}'| sed -e s/,// | sed -e s/\"//g)
if [ x$applianceVmUuid = x"" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') get applianceVmUuid failed " >> $LOGFILE
    exit
fi

abnormalFileMaxSize=$(grep "abnormalFileMaxSize" $BOOTSTRAPINFO |awk '{print $2}' | sed 's/,//g')
if [ x$abnormalFileMaxSize = x"" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') get abnormalFileMaxSize failed " >> $LOGFILE
    exit
fi


checkFileSize() {
    sizeFileM=$sizeFilesMap
    fileNum=`(echo $sizeFileM|awk '{print NF}')`
    for (( i = 1; i < $fileNum; i=$i+2 )); do
        size=$(echo $sizeFileM|cut -d " " -f$i)
        if [ $size -gt $abnormalFileMaxSize ]; then
            filePath=$(echo $sizeFileM|cut -d " " -f$((i+1)))
            info="$filePath $size"
            ret="$ret|$info"
        fi
    done
}

reportToManagementNode() {
    (echo "curl -H \"Content-Type: application/json\" -H \"commandpath: /appliancevm/abnormalfiles/report\" -X POST -d '$retToMn' http://$managementNodeIp:8080/zstack/asyncrest/sendcommand" |sh) &
}

getDiskInfo() {
    diskInfo=$(df -h | grep -e '^/dev/.da'|awk '{print $2,$3,$5}')
    echo "${diskInfo}"
}

getAbnormalFileInfoRet() {
    OLD_IFS="$IFS"
    IFS="|"
    array=$ret
    array=${array#"|"}
    for values in ${array[@]};
    do
        value1=$(echo $values|awk '{print $1}')
        value2="$(echo $values|awk '{print $2}')M"
        retJson="$retJson$(echo $template |sed  "s#var1#$value1#g" | sed "s#var2#$value2#g"),"
    done

    IFS="$OLD_IFS"
}

## monitor newly added dir
dirCount=`ls /|awk 'END{print NR}'`
if [ $dirCount -gt 22 ]; then
    dirs=$(ls /)
    for dir in dirs; do
        if ! [[ $DEFAULT_DIR =~ $dir ]]; then
            DEFAULT_MONIOTOR_DIR="${DEFAULT_MONIOTOR_DIR} /${dir}"
        fi
    done
fi

## check system file
sizeFilesMap=$(find $DEFAULT_MONIOTOR_DIR -type f -print0 | xargs -0 du -hm | sort -rh | head -n $MAX_NUM_OF_MONITOR_DIR)
maxSize=$(echo $sizeFilesMap|cut -d " " -f1)
if [ $maxSize -gt $abnormalFileMaxSize ]; then
    NEED_REPORT_MN="true"
    checkFileSize
fi


if [ x$NEED_REPORT_MN = x"true" ]; then
    getAbnormalFileInfoRet
    di=$(getDiskInfo)
    diskTotal=$(echo $di|awk '{print $1}')
    diskUsed=$(echo $di|awk '{print $2}')
    diskUsedutilization=$(echo $di|awk '{print $3}')
    retToMn=$(echo $ret_template | sed "s#var1#$applianceVmUuid#g" | sed "s#var2#${retJson%?}#g" |sed "s#var3#$diskTotal#g" | sed "s#var4#$diskUsed#g" | sed "s#var5#$diskUsedutilization#g")
    reportToManagementNode
    echo "$(date '+%Y-%m-%d %H:%M:%S') report abnormal files: $retToMn to mn" >> $LOGFILE
fi