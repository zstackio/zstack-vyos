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

path="../scripts/postinstall/"
post_install $path
exit 0