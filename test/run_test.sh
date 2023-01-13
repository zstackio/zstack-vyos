#!/bin/bash

IPTABLES_RULES_FOR_UT="/home/vyos/vyos_ut/zstack-vyos/iptables.rules"
iptables-save > ${IPTABLES_RULES_FOR_UT}

cd /home/vyos/vyos_ut/zstack-vyos
export PATH=$PATH:/home/vyos/vyos_ut/go/bin
export ACK_GINKGO_RC=true
export ACK_GINKGO_DEPRECATIONS=1.16.4
rm -rf /home/vyos/vyos_ut/testLog/*
if [ "${focus}" == "" ];then
    # make test
    ginkgo  -v -r --failFast --cover -trace -skipMeasurements && result="success"
else
    # make unittest focus=( support 1 _test.go file )
    case_dir=`find ./ -name "${focus}.go" | xargs dirname`
    ginkgo -focus=${focus} -v --failFast -trace ${case_dir} | tee output.log
    if cat output.log | grep "SUCCESS" > /dev/null; then
        result="success"
    fi
fi

if [ "${result}" == "success" ]; then
    echo "VYOS UT TEST: successfully"
else
    echo "VYOS UT TEST: failed"
fi