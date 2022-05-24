#!/bin/bash

. ./hook_function

ARCH=`uname -m`

if [ "${ARCH}" == "x86_64" ]; then
    INCLUDE_LISTS="${CONFIG_PATH}/includes-x86.list"
    INCLUDE_DIR="${FILE_LISTS_PATH}/x86"
elif [ "${ARCH}" == "aarch64" ]; then
    INCLUDE_LISTS="${CONFIG_PATH}/includes-arm.list"
    INCLUDE_DIR="${FILE_LISTS_PATH}/arm"
else
    log_info "ARCH:${ARCH} is not recognized, files will not be synced"
    exit 0
fi

function sync_file {
    file_src=${INCLUDE_DIR}/$1
    file_dst=$2/$1
    file_mode=$3
    file_owner=$4

    if [ ! -f "${file_src}" ]; then
        log_info "${file_src} not exist"
        return 1
    fi

    if ! diff ${file_src} ${file_dst} > /dev/null; then
        if [ ! -d "$2" ]; then
            mkdir -p $2
        fi
        cp -f ${file_src} ${file_dst}
    fi
    chmod ${file_mode} ${file_dst}
    chown ${file_owner} ${file_dst}
}

log_info "Start sync conf file"
remove_file_lists=`parse_conf "uninstall" ${INCLUDE_LISTS} | xargs`
if [ "${remove_file_lists}" != "" ]; then
    log_info "Remove file list: [${remove_file_lists}]"
    rm -f ${remove_file_lists}
fi

parse_conf "install" ${INCLUDE_LISTS} | while read line; do
    arg_num=`echo ${line} | awk '{print NF}'`
    if [ ${arg_num} -eq 4 ]; then
        sync_file $line
    else
        log_info "install file:[$line] format error"
    fi
done

exit 0
