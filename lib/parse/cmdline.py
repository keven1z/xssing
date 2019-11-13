import sys
import argparse
from lib.core.settings import VERSION
from lib.core.enums import HTTP


def cmdLineParser(argv=None):
    if not argv:
        argv = sys.argv
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", dest="showVersion", action="store_true",
                        help="Show program's version number and exit")
    parser.add_argument("-v", dest="verbose", type=int,
                        help="Verbosity level: 0-1 (default 0)")
    # Target options
    target = parser.add_argument_group("Target",
                                       "At least one of these options has to be provided to define the target(s)")
    target.add_argument("-u", "--url", dest="url",
                        help="Target URL (e.g. \"http://www.site.com/vuln.php?id=1\")")
    target.add_argument("-r", dest="requestFile",
                        help="Load HTTP request from a file")
    # Request options
    request = parser.add_argument_group("Request",
                                        "These options can be used to specify how to connect to the target URL")
    request.add_argument("--method", dest="method",
                         help="Force usage of given HTTP method (e.g. PUT)")
    request.add_argument("--user-agent", dest="agent",
                         help="HTTP User-Agent header value")
    request.add_argument("--data", dest="data",
                         help="Data string to be sent through POST (e.g. \"id=1\")")
    request.add_argument("--cookie", dest="cookie",
                         help="HTTP Cookie header value (e.g. \"PHPSESSID=a8d127e..\")")

    # Injection options
    injection = parser.add_argument_group("Injection",
                                          "These options can be used to specify which parameters to test for,"
                                          " provide custom injection payloads and optional tampering scripts")

    injection.add_argument("-p", dest="parameter",
                           help="Testable parameter(s)")
    injection.add_argument("--prefix", dest="prefix",
                           help="Injection payload prefix string", default='')

    injection.add_argument("--suffix", dest="suffix",
                           help="Injection payload suffix string", default='')
    # Detection options
    detection = parser.add_argument_group("Detection", "These options can be used to customize the detection phase")

    detection.add_argument("--test-all", dest="test_all", action="store_true", default=False,
                           help="test all payload")
    detection.add_argument("--level", dest="level", type=int,
                           help="Level of tests to perform (1-2, default %d)" % 1)
    # Optimization options
    optimization = parser.add_argument_group("Optimization",
                                             "These options can be used to optimize the performance of xssing")
    optimization.add_argument("--sleep", dest="sleep", type=int,
                              help="Seconds to wait before check (default 0)", default=0)
    for i in range(len(argv)):
        if "--version" in argv:
            print(VERSION)
            raise SystemExit

        elif not any(_ in argv for _ in ("-u", "--url", "-r")) and '-h' not in argv:
            errMsg = "missing a mandatory option (-d, -u,-url, -r, --update). "
            errMsg += "Use -h for help"
            import time
            time.sleep(0.1)
            parser.error(errMsg)
    try:
        (args, _) = parser.parse_known_args(argv) if hasattr(parser, "parse_known_args") else parser.parse_args(argv)
    except SystemExit:
        raise
    url = args.url
    if url is not None:
        args.url = url if any(str(url).startswith(_) for _ in ("http", "https")) else "http://" + url
    method = args.method if args.method is not None else HTTP.GET.value
    args.method = method if args.data is None else HTTP.POST.value
    return args
