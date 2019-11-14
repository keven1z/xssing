# _*_coding=utf-8_*_
try:
    import sys
    try:
        __import__("lib.utils.versioncheck")  # this has to be the first non-standard import
    except ImportError as e:
        sys.exit("[!] wrong installation detected (missing modules). Visit '' for further details")
    import traceback
    import threading
    import os
    import inspect
    from lib.core.settings import BANNER
    from lib.core.data import cmdLineOptions
    from lib.core.options import initOptions
    from lib.core.controler import start
    from lib.core.common import setPaths
    from lib.parse.cmdline import cmdLineParser
    from sys import version_info
    from lib.core.data import logger
except KeyboardInterrupt:
    errMsg = "user aborted"
    raise SystemExit(errMsg)


def banner():
    """
    This function prints xssing banner with its version
    """
    argv = sys.argv
    if "--version" not in argv:
        _ = BANNER
        print(_)


def initCmdParsing():
    cmdLineOptions.update(cmdLineParser().__dict__)
    initOptions(cmdLineOptions)


def modulePath():
    """
    This will get us the program's directory, even if we are frozen
    using py2exe
    """

    try:
        _ = sys.executable if hasattr(sys, "frozen") else __file__
    except NameError:
        _ = inspect.getsourcefile(modulePath)

    return os.path.dirname(os.path.realpath(_))


def main():
    setPaths(modulePath())
    banner()
    initCmdParsing()
    try:
        start()
    except Exception as ex:
        raise RuntimeError(ex)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        pass
    except RuntimeError as e:
        logger.critical(e)
        import traceback
        logger.critical(traceback.format_exc())
    except Exception as e:
        logger.critical(e)
        import traceback
        logger.critical(traceback.format_exc())
    finally:
        # Reference: http://stackoverflow.com/questions/1635080/terminate-a-multi-thread-python-program
        if threading.activeCount() > 1:
            os._exit(getattr(os, "_exitcode", 0))
        else:
            sys.exit(getattr(os, "_exitcode", 0))
