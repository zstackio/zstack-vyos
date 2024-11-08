#!/bin/bash

. ./hook_function

function post_install(){
    for file in `ls $1`
    do
        if [ "${file##*.}"x = "sh"x ];then
            chmod +x $1$file
            log_info "post_install: run"$1$file
            timeout 30 /bin/bash $1$file >> ${LOG_FILE} 2>&1
        fi
    done
}

systemctl daemon-reload

#stop ipvsHealthCheck
systemctl status ipvsHealthCheck > /dev/null
if [ $? -ne 0 ]; then
   pkill -9 ipvsHealthCheck ## wait zvr pidmod to start ipvsHealthCheck
else
  systemctl restart ipvsHealthCheck
fi

sudo sysctl -w net.ipv4.ip_nonlocal_bind=1
sudo sysctl -w net.ipv6.ip_nonlocal_bind=1
sudo sysctl -w net.ipv4.vs.conntrack=1

if [[ "${KERNEL_VERSION}" == "5.4.80-amd64-vyos" ]] && [[ "${ARCH}" == "x86_64" ]]; then
    lsmod | grep -q mlx5_core || modprobe mlx5_core
fi

#path="../scripts/postinstall/"
#post_install $path
exit 0