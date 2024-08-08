#!/bin/bash

. ./hook_function

services=("conntrackd")

check_service_status() {
    local service=$1

    if [ -x "/etc/init.d/$service" ]; then
        sudo /etc/init.d/"$service" status > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        else
            pgrep "$service" > /dev/null
            if [ $? -eq 0 ]; then
                return 0
            else
                return 1
            fi
        fi
    else
        pgrep "$service" > /dev/null
        if [ $? -eq 0 ]; then
            return 0
        else
            return 1
        fi
    fi
}

for service in "${services[@]}"; do
    if check_service_status "$service"; then
        log_info "$service is running, restarting it for zvr update"
        sudo /etc/init.d/"$service" restart
    else
        log_info "$service is not running. do nothing"
    fi
done