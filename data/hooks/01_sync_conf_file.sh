#!/bin/bash

. ./hook_function

FILE_CONFIG="${CONFIG_PATH}/file_config"

function sync_file {
    file_src=${FILE_LISTS_PATH}/$1
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
remove_file_lists=`parse_conf "uninstall" ${FILE_CONFIG} | xargs`
if [ "${remove_file_lists}" != "" ]; then
    log_info "Remove file list: [${remove_file_lists}]"
    rm -f ${remove_file_lists}
fi

parse_conf "install" ${FILE_CONFIG} | while read line; do
    arg_num=`echo ${line} | awk '{print NF}'`
    if [ ${arg_num} -eq 4 ]; then
        sync_file $line
    else
        log_info "install file:[$line] format error"
    fi
done

exit 0
