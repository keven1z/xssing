from lib.core.data import conf, kb
from lib.core.payloads import loadPayloads, loadBoundaries
from lib.request.url import WrappedUrl
from lib.core.settings import XSS_USERAGENT


def initOptions(inputOptions=dict):
    _setConfAttributes()
    _setKnowledgeBaseAttributes()
    _mergeOptions(inputOptions)


def _setConfAttributes():
    conf.url = None
    conf.wrappedUrl = None
    conf.method = None
    conf.cookie = None
    conf.data = None
    conf.requestFile = None
    conf.parameter = None
    conf.threads = None
    conf.actions = []
    conf.functions = []
    conf.fully = []
    conf.boundaries = []


def _setKnowledgeBaseAttributes():
    kb.targets = []
    kb.places = []
    kb.parameters = []
    kb.positions = []
    kb.testedParamed = []
    kb.no_boundaries = False


def _mergeOptions(inputOptions=dict):
    for key, value in inputOptions.items():
        conf[key] = value
    if conf.requestFile is not None:
        pass
    if conf.verbose:
        if 1 == conf.verbose:
            from lib.core.data import logger
            from lib.core.settings import LEVEL_PAYLOAD
            logger.setLevel(LEVEL_PAYLOAD)
    if conf.agent:
        headers = {'User-Agent': conf.agent}
    else:
        headers = XSS_USERAGENT
    if conf.url:
        kb.targets.append(
            WrappedUrl(url=conf.url, method=conf.method, headers=headers, cookies=conf.cookie, data=conf.data))

    loadPayloads()
    loadBoundaries()
