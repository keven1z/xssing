#!/usr/bin/env python

"""
Copyright (c) 2006-2019 sqlmap developers (http://sqlmap.org/)
See the file 'LICENSE' for copying permission
"""

import logging
import sys
from lib.core.settings import LEVEL_PAYLOAD

LOGGER = logging.getLogger("xssingLog")
logging.addLevelName(LEVEL_PAYLOAD, "PAYLOAD")


def payload(self, message, *args, **kws):
    self.log(LEVEL_PAYLOAD, message, *args, **kws)


logging.Logger.payload = payload

LOGGER_HANDLER = None
try:
    from thirdparty.ansistrm.ansistrm import ColorizingStreamHandler

    LOGGER_HANDLER = ColorizingStreamHandler(sys.stdout)
    LOGGER_HANDLER.level_map[logging.getLevelName("PAYLOAD")] = (None, "cyan", False)
except ImportError:
    LOGGER_HANDLER = logging.StreamHandler(sys.stdout)

FORMATTER = logging.Formatter("\r[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")

LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.INFO)

# 关闭pyppeteer debug日志
pyppeteer_level = logging.CRITICAL
logging.getLogger('pyppeteer').setLevel(pyppeteer_level)
logging.getLogger('websockets.protocol').setLevel(pyppeteer_level)

pyppeteer_logger = logging.getLogger('pyppeteer')
pyppeteer_logger.setLevel(logging.CRITICAL)