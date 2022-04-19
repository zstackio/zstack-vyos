#!/bin/bash

. ./hook_function

DEB_CONFIG_FILE="${CONFIG_PATH}/deb_config"
remove_lists=`parse_conf "uninstall" ${DEB_CONFIG_FILE} | xargs`
install_lists=`parse_conf "install" ${DEB_CONFIG_FILE} | xargs`
package_num=`ls ${REPOS_PATH}/*.deb | wc -l`

log_info "Start remove or install deb packages"
if [[ ! -d "${REPOS_PATH}" ]] || [[ ${package_num} -eq 0 ]]; then
    log_info "No repos dir or local packages ..."
    exit 0
fi

if [ "${remove_lists}" != "" ]; then
    log_info "Remove package list: [${remove_lists}]"
    /usr/bin/dpkg -r ${remove_lists}
fi

if [ "${install_lists}" != "" ]; then
    log_info "Install package list: [${install_lists}]"
    for package in ${install_lists}; do
        /usr/bin/dpkg -i ${REPOS_PATH}/${package}*.deb
    done
fi

exit 0
