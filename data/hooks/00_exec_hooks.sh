#!/bin/bash

cd /home/vyos/zvr/data/hooks
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
        "02_install_package.sh")
            chmod +x $f
            timeout 30 /bin/bash $f >> ${LOG_FILE} 2>&1
            ;;
        "03_load_driver.sh")
            if [ "${kernel_version}" == "5.4.80-amd64-vyos" ]; then
                chmod +x $f
                timeout 30 /bin/bash $f >> ${LOG_FILE} 2>&1
            else
                log_info "Kernel version is: ${kernel_version}, no need load driver"
            fi
            ;;
        *)
            chmod +x $f
            timeout 30 /bin/bash $f >> ${LOG_FILE} 2>&1
            ;;
    esac
done

exit 0