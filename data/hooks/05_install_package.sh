#!/bin/bash

. ./hook_function

X86_DEBS=" \
          iperf_2.0.4-5_amd64.deb \
          strace_4.5.20-2_amd64.deb \
          mlnx-ofed-kernel-modules_5.4.80-amd64-vyos_amd64.deb \
         "


################
### use for install deb packages when zvr.bin is updated
#######

log_info "[05_install_package.sh]: start exec"

if [[ "${KERNEL_VERSION}" == "5.4.80-amd64-vyos" ]] && [[ "${ARCH}" == "x86_64" ]]; then
    for file in ${X86_DEBS}; do
        if [ ! -f "${REPOS_PATH}/${file}" ]; then
            log_info "can not find deb package: [$file]"
            continue
        fi
        log_info "start install deb package: [${file}]"
        package_name=${file%%_*}
        if dpkg -l | grep -q ${package_name}; then
            log_info "package [${package_name}] is already installed"
            continue
        fi
        /usr/bin/dpkg -i ${REPOS_PATH}/${file}
    done
fi

exit 0
