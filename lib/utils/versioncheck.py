#!/usr/bin/env python

import sys
import time

PYVERSION = sys.version.split()[0]

if PYVERSION < "3.7":
    sys.exit(
        "[%s] [CRITICAL] incompatible Python version detected ('%s')."
        " To successfully run xssing you'll have to use version  3.7 or"
        " above (visit 'https://www.python.org/downloads/')" % (
            time.strftime("%X"), PYVERSION))

if __name__ == '__main__':
    print(PYVERSION)
