from lib.core.common import payloadCombined, randomStr
from lib.request.request import open
from lib.core.settings import *
from lib.core.data import kb, conf
from lib.core.enums import POSITION
from lib.core.data import logger
import copy
import urllib.parse
from bs4 import BeautifulSoup
from bs4 import Tag
from lib.position.positions import JsScriptChecker, AttributeChecker, BlockChecker
from lib.core.payloads import Agent


class Checker(object):

    def __init__(self, wrappedUrl, place, parameter):
        '''
        :param wrappedUrl:  目标URL的包裹类
        :param place: 注入的请求类型（如GET、POST）
        :param parameter: 注入的参数
        '''
        self.wrappedUrl = wrappedUrl
        self.place = place
        self.parameter = parameter

    def basicCheckXSS(self):
        '''
        测试连通性以及是否有回显
        :return: true :测试ok false：测试失败
        '''
        target = copy.deepcopy(self.wrappedUrl)
        place = self.place
        parameter = self.parameter
        infoMsg = "testing connection to the target URL(%s)" % self.wrappedUrl.url
        logger.info(infoMsg)
        msg = 'target URL(%s) ' % self.wrappedUrl.url
        payload = randomStr(length=6)
        target = payloadCombined(target=target, place=place, parameter=parameter, payload=payload)
        try:
            resp = open(target)
        except Exception:
            msg += "connect error"
            return False

        if resp is None:
            msg += 'cannot be accessed'
            logger.error(msg)
            return False
        else:
            if resp.status_code != 200:
                msg += 'status code is (%s),not equal to 200(ok)' % resp.status_code
                logger.error(msg)
                return False
            if 'Content-Type' not in resp.headers or not str(resp.headers['Content-Type']).lower().startswith(
                    'text/html'):
                msg += 'Content-Type is (%s),not text/html' % (resp.headers[
                                                                   'Content-Type'] if 'Content-Type' in resp.headers else None)
                logger.error(msg)
                return False
            page = resp.text
            if payload in page:
                msg += 'connection test pass'
                logger.info(msg)
                return True
            else:
                msg += 'random parameter value(%s) does not appear in the response text' % payload
                logger.info(msg)
                return False

    def positionCheck(self):
        payload = DETECTOR
        payload = Agent.payload(payload)
        target = copy.deepcopy(self.wrappedUrl)
        place = self.place
        parameter = self.parameter
        target = payloadCombined(target=target, place=place, parameter=parameter, payload=payload)
        resp = open(target)
        if resp is None or resp.status_code != 200:
            return False
        else:
            page = resp.text
            page = str(page)
            if payload in page:
                kb.positions = []
                kb.positions += JsScriptChecker(page, payload).check()
                kb.positions += BlockChecker(page, payload).check()
                kb.positions += AttributeChecker(page, payload).check()


def heuristicCheckXss(target, place, parameter, position):
    kb.boundaries = []
    testXss = True
    boundaries = _heuristicCheckXss(target, place, parameter, position, conf.boundaries)
    if isinstance(boundaries, bool):
        kb.no_boundaries = True
        return testXss
    if boundaries is None or len(boundaries) == 0:
        testXss = False
    else:
        kb.boundaries = boundaries
    return testXss


def _heuristicCheckXss(target, place, parameter, position, boundaries):
    '''
    :return: 匹配到的边界
    '''
    u_boundaries = []
    if position.pos == POSITION.SPECIAL_ATTR:
        u_boundaries.append(INLINE_PSEUDO_PROTOCOL_BOUNDARY)
    if position.pos == POSITION.EVE_ATTR_INSIDE:
        u_boundaries.append(INLINE_BOUNDARY)
    for b in boundaries:
        if str(position.pos.name) in POS and str(POS[str(position.pos.name)]) in b.context:
            # 若位置在标签内，且是则需要闭合标签
            ran = randomStr(2)
            if BLOCK in b.type and position.pos in (POSITION.JS_VALUE, POSITION.JS_COMMENT, POSITION.LABEL_INSIDE):
                # 判断位置在js值、js注释、属性内，并且标签需要闭合，边界增加闭合操作
                if position.tag.name.lower() in CLOSED_LABEL:
                    payload = b.prefix = b.prefix.replace(REPLACE_TAG, position.tag.name)
                else:
                    u_boundaries.append(BLOCK_BOUNDARY)
                    return u_boundaries
            else:
                payload = ran + b.prefix
            if payload is None:
                continue
            target = payloadCombined(target, place, parameter, payload)
            resp = open(target)
            if resp is not None and resp.status_code == 200 and resp.content is not None and urllib.parse.unquote(
                    payload) in resp.text:
                # 若位置在属性内，需要进一步进行语义分析判定是否注入成功
                if position.pos in (
                        POSITION.EVE_ATTR_INSIDE, POSITION.NON_EVE_ATTR_INSIDE,
                        POSITION.SPECIAL_ATTR):
                    if not _token_check(position, ran, str(resp.text), b.type):
                        continue
                u_boundaries.append(b)
    return u_boundaries


def _token_check(position, payload, content, type):
    # 语义分析该边界是否有效
    bs4 = BeautifulSoup(content, 'html.parser')
    for attr_name in NON_EVENT_ATTRIBUTE + EVENT_ATTRIBUTE:
        if type == INLINE:
            tag = bs4.find(attrs={attr_name: payload})
            if isinstance(tag, Tag) and len(tag.attrs) > len(position.tag.attrs):
                return True
        elif type == BLOCK:
            # 块注入类型边界不需要语义分析
            tag = bs4.find(attrs={attr_name: payload})
            if isinstance(tag, Tag):
                return True
    return False
