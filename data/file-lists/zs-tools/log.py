#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import sys
import traceback

LOG_PATH = '/var/log/zstack/zs-tools.log'


def get_logger(name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(LOG_PATH)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d:%(funcName)s - %(message)s"))
    logger.addHandler(file_handler)
    return logger


def log_exce_traceback():
    cmd_type, value, tb = sys.exc_info()
    exception = traceback.format_exception(cmd_type, value, tb)
    get_logger(__name__).debug(''.join(exception))
