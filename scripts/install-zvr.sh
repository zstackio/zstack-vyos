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
SUFFIX="_$ARCH"

id -u vyos > /dev/null 2>&1 && USER="vyos" || USER="zstack"

dpkg -l dnsmasq > /dev/null 2>&1
if [ $? -ne 0 -a x"$ARCH" = x"aarch64" -a x"$USER" = x"vyos" ];then
    rm -rf /etc/dnsmasq.conf
    sudo dpkg -i dnsmasq_pkg/*
fi
sudo mkdir -p /var/run/dnsmasq/
sudo chmod 777 /var/run/dnsmasq/
sudo rm -rf /home/vyos/zvr/ntp/conf/ntpConfig* ##old bug, tempfile is not removed

OSVERSION=`uname -r`
if [ "$OSVERSION" = "3.13.11-1-amd64-vyos" ]; then
  sudo cp  grub.cfg.3.13 /boot/grub/grub.cfg
elif [ "$OSVERSION" = "5.4.80-amd64-vyos" ]; then
  sudo cp  grub.cfg.5.4.80 /boot/grub/grub.cfg
fi

ZVR_DATA_DIR="/home/$USER/zvr/data"
ZVR_DATA_DIR_TEMP="/home/$USER/zvr/data_temp"
if [ -d ${ZVR_DATA_DIR} ]; then
	sudo rm -rf ${ZVR_DATA_DIR}
fi
sudo mkdir -p ${ZVR_DATA_DIR_TEMP}
tar zxf zvr-data.tar.gz -C ${ZVR_DATA_DIR_TEMP}

# rsync data_temp/ to data
sudo rsync -a ${ZVR_DATA_DIR_TEMP}/ ${ZVR_DATA_DIR}
if [ -d ${ZVR_DATA_DIR_TEMP} ]; then
    sudo rm -rf ${ZVR_DATA_DIR_TEMP}
fi

if [ -f "${ZVR_DATA_DIR}/hooks/00_exec_hooks.sh" ]; then
    sudo chmod +x /home/$USER/zvr/data/hooks/00_exec_hooks.sh
    sudo /bin/bash -x /home/$USER/zvr/data/hooks/00_exec_hooks.sh $USER
fi

exit 0
