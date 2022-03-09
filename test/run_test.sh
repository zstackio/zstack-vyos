#!/bin/bash

cd /home/vyos/vyos_ut/zstack-vyos
export PATH=$PATH:/home/vyos/vyos_ut/go/bin
ginkgo  -v -r --failFast --cover -trace -skipMeasurements
if [ $? -eq 0 ]; then
  echo "VYOS UT TEST: successfully"
else
  echo "VYOS UT TEST: failed"
fi