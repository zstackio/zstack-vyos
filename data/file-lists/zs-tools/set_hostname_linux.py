import argparse
import json
import signal
import json

import shell
from log import get_logger

parser = argparse.ArgumentParser(description='set hostname')
parser.add_argument('hostname')
parser.add_argument('default_ip')
args = parser.parse_args()
hostname = args.hostname
default_ip = args.default_ip

logger = get_logger(__name__)

def _call_if_err_raise(cmd):
    ret_code, stdout, stderr = shell.call(cmd)
    if ret_code != 0:
        raise ConfigException(stderr)
    return stdout

if __name__ == '__main__':
    logger.debug('set hostname: {}, ip {}'.format(hostname, default_ip))

    ret = {}
    _call_if_err_raise("sudo hostnamectl set-hostname {}".format(hostname))
    if default_ip != "":
        _call_if_err_raise("sed -i '/{}/d' /etc/hosts > /etc/hosts".format(hostname))
        _call_if_err_raise("echo '{} {}' >> /etc/hosts".format(default_ip, hostname))

    ret['result'] = 'success'
    print(json.dumps(ret))