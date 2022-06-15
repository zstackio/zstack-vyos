#!/bin/bash

. ./hook_function

X86_DEBS=" \
          iperf_2.0.4-5_amd64.deb \
          strace_4.5.20-2_amd64.deb \
         "


################
### use for install deb packages when zvr.bin is updated
#######

log_info "[05_install_package.sh]: start exec"

if [[ "${KERNEL_VERSION}" == "5.4.80-amd64-vyos" ]] && [[ "${ARCH}" == "x86_64" ]]; then
    for i in ${X86_DEBS}; do
        if [ ! -f "${REPOS_PATH}/${i}" ]; then
            log_info "can not find deb package: [$i]"
            continue
        fi
        log_info "start install deb package: [${i}]"
        /usr/bin/dpkg -i ${REPOS_PATH}/${i}
    done
fi

exit 0
