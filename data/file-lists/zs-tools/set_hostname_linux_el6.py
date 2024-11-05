import json
import sys
import shell
from log import get_logger


class ConfigException(Exception):
    pass


if len(sys.argv) < 3:
    print("Usage: script.py <hostname> <default_ip>")
    sys.exit(1)

hostname = sys.argv[1]
default_ip = sys.argv[2]

logger = get_logger(__name__)


def _call_if_err_raise(cmd):
    ret_code, stdout, stderr = shell.call(cmd)
    if ret_code != 0:
        raise ConfigException(stderr)
    return stdout


def is_suse():
    try:
        with open('/etc/os-release', 'r') as f:
            os_release = f.read()
        return 'suse' in os_release.lower()
    except FileNotFoundError:
        return False


if __name__ == '__main__':
    logger.debug('set hostname: %s, ip %s' % (hostname, default_ip))

    ret = {}

    if is_suse():
        _call_if_err_raise("hostname %s" % hostname)
        _call_if_err_raise("echo '%s' > /etc/HOSTNAME" % hostname)
    else:
        _call_if_err_raise("hostname %s" % hostname)
        _call_if_err_raise("echo 'HOSTNAME=%s' | tee -a /etc/sysconfig/network" % hostname)

    if default_ip != "":
        _call_if_err_raise("sed -i '/%s/d' /etc/hosts" % hostname)
        _call_if_err_raise("echo '%s %s' >> /etc/hosts" % (default_ip, hostname))

    ret['result'] = 'success'
    print(json.dumps(ret))
