#!/usr/bin/env python
# encoding: utf-8
import argparse
import os.path
from zstacklib import *
from datetime import datetime

# create log
logger_dir = "/home/vyos/zvr"
create_log(logger_dir)
banner("Starting to deploy zstack vyos agent")
start_time = datetime.now()
# set default value
file_root = "files/vyos"
post_url = ""
pkg_zvr = ""
pkg_zvrboot = ""
remote_root = ""
remote_user = "vyos"
remote_pass = None
remote_port = None
require_python_env = "false"

# get parameter from shell
parser = argparse.ArgumentParser(description='Deploy zstack vyos to host')
parser.add_argument('-i', type=str, help="""specify inventory host file
                        default=/etc/ansible/hosts""")
parser.add_argument('--private-key', type=str, help='use this file to authenticate the connection')
parser.add_argument('-e', type=str, help='set additional variables as key=value or YAML/JSON')

args = parser.parse_args()
argument_dict = eval(args.e)

# update the variable from shell arguments
locals().update(argument_dict)

host_post_info = HostPostInfo()
host_post_info.host_inventory = args.i
host_post_info.host = host
host_post_info.post_url = post_url
host_post_info.private_key = args.private_key
host_post_info.remote_user = remote_user
host_post_info.remote_pass = remote_pass
host_post_info.remote_port = remote_port
if remote_pass is not None and remote_user != 'root':
    host_post_info.become = True

copy_arg = CopyArg()
copy_arg.src = os.path.join(file_root, pkg_zvrboot)
copy_arg.dest = os.path.join(remote_root, pkg_zvrboot)
copy(copy_arg, host_post_info)

run_remote_command("bash %s" % copy_arg.dest)

copy_arg = CopyArg()
copy_arg.src = os.path.join(file_root, pkg_zvr)
copy_arg.dest = os.path.join(remote_root, pkg_zvr)
copy(copy_arg, host_post_info)

run_remote_command("bash %s" % copy_arg.dest)

sys.exit(0)
