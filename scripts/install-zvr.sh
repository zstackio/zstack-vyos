#!/bin/bash
err_exit() {
    if [ $? -ne 0 ]; then
        echo $1
        exit 1
    fi
}

tar xzf data.tar.gz
err_exit "unable to untar data.tar.gz"
set -u

ARCH=`uname -m`
LABLE=''
[ x"$ARCH" != x"x86_64" ] && LABLE="_$ARCH"

dpkg -l dnsmasq
if [ $? -ne 0 -a x"$ARCH" = x"aarch64" ];then
    rm -rf /etc/dnsmasq.conf
    sudo dpkg -i dnsmasq_pkg/*
fi
sudo mkdir -p /var/run/dnsmasq/
sudo chmod 777 /var/run/dnsmasq/

OSVERSION=`uname -r`
if [ "$OSVERSION" = "3.13.11-1-amd64-vyos" ]; then
  sudo cp  grub.cfg.3.13 /boot/grub/grub.cfg
elif [ "$OSVERSION" = "5.4.80-amd64-vyos" ]; then
  sudo cp  grub.cfg.5.4.80 /boot/grub/grub.cfg
fi

ZVR_DATA_DIR="/home/vyos/zvr/data"
ZVR_DATA_DIR_TEMP="/home/vyos/zvr/data_temp"
if [ -d ${ZVR_DATA_DIR_TEMP} ]; then
	sudo rm -rf ${ZVR_DATA_DIR_TEMP}
fi
sudo mkdir -p ${ZVR_DATA_DIR_TEMP}
tar zxf zvr-data.tar.gz -C ${ZVR_DATA_DIR_TEMP}

# rsync data_temp/ to data
sudo rsync -a ${ZVR_DATA_DIR_TEMP}/ ${ZVR_DATA_DIR}
if [ -d ${ZVR_DATA_DIR_TEMP} ]; then
	sudo rm -rf ${ZVR_DATA_DIR_TEMP}
fi
if [ -f "${ZVR_DATA_DIR}/hooks/00_exec_hooks.sh" ]; then
    sudo chmod +x /home/vyos/zvr/data/hooks/00_exec_hooks.sh
    sudo /bin/bash /home/vyos/zvr/data/hooks/00_exec_hooks.sh
fi

exit 0
