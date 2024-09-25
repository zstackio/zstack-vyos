#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import functools

import shell


CARRIER_ON = 'on'
CARRIER_OFF = 'off'
NO_CARRIER = 'no'


def is_ipv4(ip_address):
    compile_ip = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)')
    if compile_ip.match(ip_address):
        return True
    else:
        return False


def netmask_to_prefix(netmask):
    '''
    :param netmask: netmask ip addr (eg: 255.255.255.0), or IPv4/IPv6 prefix length (e.g., '24' or '64')
    :return: equivalent cidr number to given netmask ip (eg: 24)
    '''
    if netmask.lower() == 'none':
        return 32
    if netmask.isdigit():
        prefix_len = int(netmask)
        if 0 <= prefix_len <= 128:
            return prefix_len
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])


def prefix_to_netmask(prefix):
    '''prefix to netmask'''
    prefix = int(prefix)
    netmask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
    return (str((0xff000000 & netmask) >> 24) + '.' +
            str((0x00ff0000 & netmask) >> 16) + '.' +
            str((0x0000ff00 & netmask) >> 8) + '.' +
            str((0x000000ff & netmask)))


def load_json_from_file(path):
    with open(path, 'r') as fp:
        return json.load(fp)


def find_nic_list_by_mac(mac):
    '''find nic list by mac'''
    nic_list = []
    for nic in os.listdir('/sys/class/net'):
        if os.path.exists('/sys/class/net/' + nic + '/address'):
            with open('/sys/class/net/' + nic + '/address') as f:
                if f.read().strip() == mac:
                    nic_list.append(nic)
    return nic_list


def find_bond_name_by_mac(mac):
    '''find bond name by mac'''
    nic_list = find_nic_list_by_mac(mac)
    for nic in nic_list:
        if is_bond(nic):
            return nic

def is_device_exists(dev):
    if not dev:
        return False
    path = "/sys/class/net/%s" % dev
    return os.path.exists(path)

def is_bond(dev):
    if not dev:
        return False
    path = "/sys/class/net/%s/bonding" % dev
    return os.path.exists(path)


def is_virtio_nic(dev):
    if not dev:
        return False
    path = "/sys/class/net/%s/device" % dev
    if os.path.exists(path):
        real_path = os.path.realpath(path)
        pattern = re.compile(r'^/sys/devices/(.*/)?virtio')
        if pattern.match(real_path):
            return True
    return False


def is_physical_nic(dev):
    if not dev:
        return False
    path = "/sys/class/net/%s" % dev
    if os.path.exists(path):
        real_path = os.path.realpath(path)
        pattern = re.compile(r'^/sys/devices/(.*/)?pci[0-9a-fA-F]')
        if pattern.match(real_path):
            return True
    return False


def find_bond_slaves(bond_name):
    if not is_device_exists(bond_name) or not is_bond(bond_name):
        return []

    path = "/sys/class/net/%s/bonding/slaves" % bond_name
    if not os.path.exists(path):
        return []

    with open(path, 'r') as fd:
        return fd.read().strip().split()


def get_master_device(dev):
    if not dev:
        return None
    path = "/sys/class/net/%s/master" % dev
    if not os.path.exists(path):
        return None

    return os.path.basename(os.readlink(path))


def retry(times=3, sleep_time=5):
    def wrap(f):
        @functools.wraps(f)
        def inner(*args, **kwargs):
            orig_except = None
            for i in range(0, times):
                try:
                    return f(*args, **kwargs)
                except Exception as err:
                    orig_except = err
                    time.sleep(sleep_time)
            raise orig_except

        return inner
    return wrap


def wait_callback_success(callback, callback_data=None, timeout=5, interval=1, ignore_exception=False):
    '''wait callback success'''
    count = time.time()
    timeout = timeout + count
    while count < timeout:
        try:
            rsp = callback(callback_data)
            if rsp:
                return True
            time.sleep(interval)
        except Exception as e:
            if not ignore_exception:
                raise e
            time.sleep(interval)
        finally:
            count = time.time()
    return False


def is_validate_netplan_config(config):
    def _get_indent(line):
        return len(line) - len(line.lstrip())

    lines = config.split('\n')
    for line in lines:
        indent = _get_indent(line)
        line_str = line.strip()
        if not line_str or line_str.startswith('#'):
            continue
        if line_str.endswith(':'):
            if len(lines) == lines.index(line) + 1:
                return False
            next_line_str = lines[lines.index(line) + 1].strip()
            next_line_indent = _get_indent(lines[lines.index(line) + 1])
            if next_line_indent <= indent and next_line_str and not next_line_str.startswith('-'):
                return False

    return True


def get_nic_info_by_name(nic_name):
    '''get nic info by name'''
    nic_info = {}
    if not is_device_exists(nic_name):
        return nic_info
    code, stdout, _ = shell.call('ip addr show %s' % nic_name)
    if code != 0 or not stdout:
        return nic_info

    nic_info['ipv4'] = []
    nic_info['ipv6'] = []
    lines = stdout.split('\n')
    for line in lines:
        line_str = line.strip()
        line_str_list = line_str.split()
        if not line_str:
            continue
        if 'state' in line_str:
            nic_info['state'] = line_str_list[line_str_list.index('state') + 1]
        if 'mtu' in line_str:
            nic_info['mtu'] = int(line_str_list[line_str_list.index('mtu') + 1])
        if line_str.startswith('link/ether'):
            nic_info['mac'] = line_str_list[1]
        if line_str.startswith('inet '):
            nic_info['ipv4'].append({'address': line_str_list[1].split('/')[0], 'netmask': line_str_list[1].split('/')[1], 'version': 4})
        if line_str.startswith('inet6 '):
            nic_info['ipv6'].append({'address': line_str_list[1].split('/')[0], 'netmask': line_str_list[1].split('/')[1], 'version': 6})

    return nic_info
