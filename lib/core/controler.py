from lib.core.data import conf, kb, logger
from lib.request.url import WrappedUrl
from lib.core.checks import Checker, heuristicCheckXss, payloadCombined
from lib.core.common import findParameterName, dataToStdout, readInput
from lib.core.payloads import getPayload
from lib.request.chromium.exec import ChromiumRequestError
from lib.request.xssdrive import XSSCheckRequest
import progressbar
import time


def start():
    if not kb.targets:
        raise SystemExit('No Found target')
    for target in kb.targets:
        assert isinstance(target, WrappedUrl)
        scan(target)


def scan(target):
    findParameterName(target, conf.parameter)
    count = len(kb.parameters) * len(kb.places)
    if count == 0:
        logger.error('Not Found injection parameter from %s' % target.url)
    for place in kb.places:
        for parameter in kb.parameters:
            logger.info("testing %s parameter '%s'" % (place.value, parameter))
            checker = Checker(target, place, parameter)
            count -= 1
            if not checker.basicCheckXSS():
                continue
            # 位置检测
            checker.positionCheck()

            if len(kb.positions) > 0:
                message = "%s parameter '%s' is existed in（" % (place.value, parameter)
                for pos in kb.positions:
                    message = message + str(pos.line) + ','
                message = message + ')'
                logger.info(message)
            else:
                message = "%s parameter '%s' has no injection position" % (place.value, parameter)
                logger.warn(message)

            if injection(target, place, parameter):
                if count != 0:
                    message = "%s parameter '%s' is vulnerable,Do you " \
                              "want to keep testing the others(if any)? [y/N]" % (
                                  place.value, parameter)
                    if not readInput(message, default='N', boolean=True):
                        break
                else:
                    break
        if len(kb.testedParamed) == 0:
            msg = 'target URL might not be injectable'
            logger.warn(msg)
            return
        _formatInjection()


def injection(target, place, parameter):
    testXss = False
    payloads_dict = dict()
    for position in kb.positions:
        info = 'heuristic (basic) test shows that %s parameter \'%s\' position(%s)' % (
            place.value, parameter, position.line)
        if not heuristicCheckXss(target, place, parameter, position):
            info += 'might not be injectable'
            logger.warn(info)
            continue
        info += 'might be injectable'
        logger.info(info)
        payloads = getPayload(position)
        if payloads is None or len(payloads) == 0:
            msg = 'position(%s) no payload generated' % position.line
            logger.warn(msg)
        else:
            payloads_dict[position] = payloads

    if len(payloads_dict) == 0:
        return False
    payloads_sorted = sorted(payloads_dict.items(), key=lambda item: len(item[1]))

    xss_drive = XSSCheckRequest()
    for payload in payloads_sorted:
        position = payload[0]
        payloads = payload[1]
        logger.info('Testing position(%s)' % position.line)
        i = 0
        bar = None
        if conf.verbose < 1:
            bar = progressbar.ProgressBar(prefix="payload testing", max_value=progressbar.UnknownLength)
        for payload in payloads:
            if conf.verbose >= 1:
                logger.payload(payload.payload)
            else:
                i += 1
                bar.update(i)
            target = payloadCombined(target, place, parameter, payload.payload)
            trigger = payload.trigger if 'trigger' in payload else None
            xss_info = {'trigger': trigger, 'func': payload.func, 'payload': payload.payload}
            target.kwargs.update(xss_info)

            try:
                # 请求前睡眠时间
                time.sleep(conf.sleep)
                xss_drive.request(target)
                if xss_drive.is_exist_xss():
                    paramKey = (target, place.value, parameter, payload.payload)
                    kb.testedParamed.append(paramKey)
                    testXss = True
                    xss_drive.clear()
                    if not conf.test_all:
                        if bar is not None:
                            bar.finish()
                        time.sleep(0.2)
                        msg = 'Found xss in %s parameter(%s)' % (place.value, parameter)
                        logger.info(msg)
                        return testXss
            except KeyboardInterrupt:
                raise KeyboardInterrupt
            except ChromiumRequestError as e:
                logger.debug(e)
        if bar is not None:
            bar.finish()
    return testXss


def _formatInjection():
    time.sleep(0.1)
    for (target, place, parameter, payload) in kb.testedParamed:
        data = "Parameter: %s (%s)\n" % (place, parameter)
        data += "\tPayload: %s\n" % payload
        dataToStdout(data, type=0)
