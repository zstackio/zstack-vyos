#!/bin/bash

. ./hook_function

ARCH=`uname -m`

if [ "${ARCH}" == "x86_64" ]; then
    PACKAGE_LISTS="${CONFIG_PATH}/packages-x86.list"
    PACKAGE_REPOS="${REPOS_PATH}/x86"
elif [ "${ARCH}" == "aarch64" ]; then
    PACKAGE_LISTS="${CONFIG_PATH}/packages-arm.list"
    PACKAGE_REPOS="${REPOS_PATH}/arm"
else
    log_info "ARCH:${ARCH} is not recognized, deb packages will not be install or remove"
    exit 0
fi

package_num=`ls ${PACKAGE_REPOS}/*.deb | wc -l`
if [[ ! -d "${PACKAGE_REPOS}" ]] || [[ ${package_num} -eq 0 ]]; then
    log_info "No repos dir or local packages ..."
    exit 0
fi

log_info "Start remove or install deb packages"
remove_lists=`parse_conf "uninstall" ${PACKAGE_LISTS} | xargs`
install_lists=`parse_conf "install" ${PACKAGE_LISTS} | xargs`

if [ "${remove_lists}" != "" ]; then
    log_info "Remove package list: [${remove_lists}]"
    /usr/bin/dpkg -r ${remove_lists}
fi

if [ "${install_lists}" != "" ]; then
    log_info "Install package list: [${install_lists}]"
    for package in ${install_lists}; do
        /usr/bin/dpkg -i ${PACKAGE_REPOS}/${package}*.deb
    done
fi

exit 0
