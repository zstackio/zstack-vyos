#!/bin/bash

. ./hook_function

services=("Hostname" "Vim")

set_zvr_default_hostname() {
    if [ -f /usr/bin/hostnamectl ]; then
      current_hostname=$(hostname)
      if [ "$current_hostname" != "vrouter" ]; then
          log_info "Setting hostname to vrouter"
          hostnamectl set-hostname vrouter
          echo "vrouter" > /etc/hostname
      else
          log_info "Hostname is already set to vrouter, no changes needed."
      fi
    fi
}

set_zvr_vim() {
    if [ -f /etc/vimrc ]; then
      log_info "Configuring vim for all users with default syntax highlighting"
      if ! grep -q "syntax on" /etc/vimrc; then
          echo "syntax on" >> /etc/vimrc
          log_info "Syntax highlighting enabled in /etc/vimrc"
      else
          log_info "Syntax highlighting is already enabled in /etc/vimrc"
      fi
    fi
}

for service in "${services[@]}"; do
    log_info "$service start to configuration"
    if [ "$service" == "Hostname" ]; then
        set_zvr_default_hostname
    fi
    if [ "$service" == "Vim" ]; then
        set_zvr_vim
    fi
done
