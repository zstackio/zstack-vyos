#!/bin/bash

. ./hook_function

log_info "Start load driver"

lsmod | grep "i40e" > /dev/null || /sbin/modprobe i40e
lsmod | grep "ixgbe" > /dev/null || /sbin/modprobe ixgbe
lsmod | grep "bnx2x" > /dev/null || /sbin/modprobe bnx2x

i40e_mod_path=`/sbin/modinfo -n i40e`
ixgbe_mod_path=`/sbin/modinfo -n ixgbe`
bnx2x_mod_path=`/sbin/modinfo -n bnx2x`

if lsmod | grep "i40e" > /dev/null; then
    log_info "i40e is reload, modules path is ${i40e_mod_path}"
fi
if lsmod | grep "i40e" > /dev/null; then
    log_info "ixgbe is reload, modules path is ${ixgbe_mod_path}"
fi
if lsmod | grep "i40e" > /dev/null; then
    log_info "bnx2x is reload, modules path is ${bnx2x_mod_path}"
fi

exit 0
