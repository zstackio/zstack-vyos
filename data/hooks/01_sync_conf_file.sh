#!/bin/bash

. ./hook_function

function sync_zvr_file {
    file_name=$1
    file_dst=$2
    file_mode=$3
    file_owner=$4
    dst_dir=`dirname $2`
    file_src=${FILE_LISTS_PATH}/$1

    if [[ -z $1 ]] || [[ -z $2 ]] || [[ -z $3 ]] || [[ -z $4 ]]; then
        log_info "sync_zvr_file error: params no enough[$1 $2 $3 $4]"
        return 1
    fi

    if [ ! -f "${file_src}" ]; then
        log_info "sync_boosync_zvr_file  error: file [${file_src}] not exist"
        return 1
    fi

    if [ ! -d "${dst_dir}" ]; then
        mkdir -p ${dst_dir}
    fi

    log_info "sync_zvr_file: src[${file_name}] to dst[${file_dst}], mode is:[${file_mode}], owner is:[${file_owner}]"
    if ! diff ${file_src} ${file_dst} > /dev/null; then
        cp -f ${file_src} ${file_dst}
    fi
    chmod ${file_mode} ${file_dst}
    chown ${file_owner} ${file_dst}
}

################
### use for sync zvr files when zvr.bin is updated
#######

log_info "[01_sync_conf_file.sh]: start exec"

mkdir -p /home/$USER/zvr/keepalived/script/
chmod -R +r /var/mail
chown -R root:root /var/mail

if [ "${USER}" == "vyos" ]; then
    BIN_PATH=$VYATTA_BIN_PATH
else 
    BIN_PATH=$USER_BIN_PATH
fi

ZVR_ROOT_PATH="/home/${USER}/zvr"

OS="vyos 1.1.7"
if [ -f /etc/system-release ]; then
  OS=`cat /etc/system-release | awk '{print $1,$2,$3}'`
fi

if [ "${OS}" == "openEuler release 22.03" ]; then
  UPDATE_ZVR_FILE="${CONFIG_PATH}/update-zvr_euler2203.install"
fi

sed -i "s%__ZVR_ROOT_PATH__%${ZVR_ROOT_PATH}%g"   ${UPDATE_ZVR_FILE}
sed -i "s%__BIN_PATH__%${BIN_PATH}%g"             ${UPDATE_ZVR_FILE}
sed -i "s%__USER__%${USER}%g"                     ${UPDATE_ZVR_FILE}

if [ ! -f "${UPDATE_ZVR_FILE}" ]; then
    log_info "can not find ${UPDATE_ZVR_FILE}, should check data directory"
    exit 0
fi

log_info "start sync generic file"
gen_file=`sed -n "/${FLAG_GEN}/,/^\[\[/p" ${UPDATE_ZVR_FILE} | sed '/^[#\[]/d;/^$/d'`
echo "${gen_file}" | while read line; do
    sync_zvr_file ${line}
done



if [ "${ARCH}" == "x86_64" ]; then
    log_info "start sync x86 zvr-update file"
    x86_file=`sed -n "/${FLAG_X86}/,/^\[\[/p" ${UPDATE_ZVR_FILE} | sed '/^[#\[]/d;/^$/d'`
    echo "${x86_file}" | while read line; do
        sync_zvr_file ${line}
    done
elif [ "${ARCH}" == "aarch64" ]; then
    log_info "start sync arm zvr-update file"
    arm_file=`sed -n "/${FLAG_ARM}/,/^\[\[/p" ${UPDATE_ZVR_FILE} | sed '/^[#\[]/d;/^$/d'`
    echo "${arm_file}" | while read line; do
        sync_zvr_file ${line}
    done
elif [ "${ARCH}" == "loongarch64" ]; then
    log_info "start sync loong zvr-update file"
    loong_file=`sed -n "/${FLAG_LOONG}/,/^\[\[/p" ${UPDATE_ZVR_FILE} | sed '/^[#\[]/d;/^$/d'`
    echo "${loong_file}" | while read line; do
        sync_zvr_file ${line}
    done
else
    log_info "ARCH:${ARCH} is not recognized,"
fi

exit 0
