#!/bin/bash

USER=$1
cd /home/$USER/zvr/data/hooks
. ./hook_function
kernel_version=`uname -r`

echo "$(date -d today '+%Y%m%d %H:%M:%S') - Start Run Hooks"  > ${LOG_FILE}

if [ ! -d "${HOOKS_PATH}" ]; then
    log_info "Can not find hooks srcipt, will exit"
    exit 0
fi

for f in *.sh; do
    case "$f" in
        "00_exec_hooks.sh")
            continue
            ;;
        *)
            chmod +x $f
            timeout 30 /bin/bash -x $f >> ${LOG_FILE} 2>&1
            ;;
    esac
done

exit 0
