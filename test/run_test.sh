#!/bin/bash

cd /home/vyos/vyos_ut/zstack-vyos
export PATH=$PATH:/home/vyos/vyos_ut/go/bin
rm -rf /home/vyos/vyos_ut/testLog/*
if [ "${focus}" == "" ];then
    # make test
    ginkgo  -v -r --failFast --cover -trace -skipMeasurements && result="success"
else
    # make unittest focus=( support 1 _test.go file )
    case_folder="$(find . -type f | grep ${focus})"
    cd $(dirname $case_folder)
    sudo -u root PATH=$PATH:/home/vyos/vyos_ut/go/bin ACK_GINKGO_RC=true ACK_GINKGO_DEPRECATIONS=1.16.4 /home/vyos/vyos_ut/go/bin/ginkgo -v --trace --skipMeasurements --focus=${focus} > temp.log 2>&1
    if [ $? -eq 0 ];then
        result="success"
    fi
    sed -i "s/.\[[0-9]*m//g" temp.log
    if [ ! -f /home/vyos/vyos_ut/testLog/${focus}.log ];then
        echo "==========================PR System==========================" >> /home/vyos/vyos_ut/testLog/${focus}.log
        echo "No testLog generated in _test.go, down below is ginkgo output" >> /home/vyos/vyos_ut/testLog/${focus}.log
        echo "=============================================================" >> /home/vyos/vyos_ut/testLog/${focus}.log
    else
        echo "===========================PR System===========================" >> /home/vyos/vyos_ut/testLog/${focus}.log
        echo "Above is log generated in _test.go, down below is ginkgo output" >> /home/vyos/vyos_ut/testLog/${focus}.log
        echo "===============================================================" >> /home/vyos/vyos_ut/testLog/${focus}.log
    fi
    cat temp.log >> /home/vyos/vyos_ut/testLog/${focus}.log
fi

if [ "${result}" == "success" ]; then
    echo "VYOS UT TEST: successfully"
else
    echo "VYOS UT TEST: failed"
fi