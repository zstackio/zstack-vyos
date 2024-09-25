#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import subprocess

from log import get_logger

logger = get_logger(__name__)


# instead of closing [3, ulimit -n)
def _linux_close_fds(self, but):
    for fd in [int(n) for n in os.listdir('/proc/%d/fd' % os.getpid())]:
        if fd > 2 and fd != but:
            try:
                os.close(fd)
            except:
                pass


subprocess.Popen._close_fds = _linux_close_fds


def get_process(cmd, shell=None, workdir=None, pipe=None, executable=None):
    if pipe:
        return subprocess.Popen(cmd, shell=shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                close_fds=True, executable=executable, cwd=workdir, universal_newlines=True)
    else:
        return subprocess.Popen(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                close_fds=True, executable=executable, cwd=workdir, universal_newlines=True)


class ShellCmd(object):
    '''
    classdocs
    '''
    stdout = None  # type: str

    def __init__(self, cmd, workdir=None, pipe=True):
        '''
        Constructor
        '''
        self.cmd = cmd
        self.process = get_process(cmd, True, workdir, pipe, "/bin/bash")

        self.stdout = None
        self.stderr = None
        self.return_code = None

    def __call__(self, logcmd=True):
        if logcmd:
            logger.debug(self.cmd)

        try:
            (self.stdout, self.stderr) = self.process.communicate()
        except KeyboardInterrupt:
            (self.stdout, self.stderr) = self.process.communicate()

        self.return_code = self.process.returncode

        if logcmd:
            logger.debug("command finished， r {0}, o {1}, e {2}".format(
                self.return_code,
                self.stdout,
                self.stderr))

        return self.return_code, self.stdout, self.stderr


def call(cmd, workdir=None):
    return ShellCmd(cmd, workdir)()


def run(cmd, workdir=None):
    ret_code, _, _ = ShellCmd(cmd, workdir)()
    return ret_code == 0
