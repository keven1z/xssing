#
import os
from lib.core.data import kb, conf
from lib.core.settings import PAYLOAD_XML_FILES, INLINE, CODE, BLOCK, TAG, XSS_MESSAGE, PSEUDO_PROTOCOL, \
    PSEUDO_PROTOCOL_NAME, BLOCK_BOUNDARY, INLINE_BOUNDARY, INLINE_PSEUDO_PROTOCOL_BOUNDARY, ENCODE_URL, ENCODE_NONE
from lib.core.data import paths
from lib.core.datatype import Payload
from lib.core.exceptions import XssingInstallationException
from lib.core.common import randomStr, absoluteUrlEncode
from xml.etree import ElementTree as et
from lib.core.datatype import AttribDict
from lib.core.datatype import Position
import urllib.parse


class Agent(object):
    @staticmethod
    def payload(payload):
        if isinstance(payload, Payload):
            f = func = randomStr(4)
            msg = XSS_MESSAGE
            encode = payload.encode
            if payload.trigger is not None:
                payload.trigger = payload.trigger.replace('?', f).replace('$', msg)
            if encode == ENCODE_URL:
                f = absoluteUrlEncode(func)
                msg = absoluteUrlEncode(msg)
            payload.func = func
            payload.value = payload.value.replace('?', f).replace('$', msg)
            payload.value = conf.prefix + payload.value + conf.suffix

        return payload


def getPayload(position):
    payloads = []
    if len(kb.boundaries) == 0:
        return None
    for boundary in kb.boundaries:
        if not isinstance(boundary, str):
            suffix = boundary.suffix if 'suffix' in boundary else ''
            prefix = boundary.prefix
            # 添加边界的前缀后缀
            payloads += genPayload(boundary.type, position)
            for payload_obj in payloads:
                payload_obj.value = prefix + payload_obj.value + suffix
        else:
            payloads += genPayload(type=BLOCK) if boundary == BLOCK_BOUNDARY else []
            payloads += genPayload(type=PSEUDO_PROTOCOL,
                                   position=position) if boundary == INLINE_PSEUDO_PROTOCOL_BOUNDARY else []
            payloads += gen_function(position) if boundary == INLINE_BOUNDARY else []
    abs_payloads = []
    for payload in payloads:
        payload = Agent.payload(payload)
        abs_payloads.append(payload)
    return abs_payloads


def genPayload(type, position=None):
    payloads = []
    if BLOCK in type:
        # 获取完整html tag，添加到payload中
        payloads = payloads + genFullyTag()
        payloads = payloads + gen_block()
    if INLINE in type:
        payloads += gen_inline(position)
    if CODE in type:
        payloads += gen_code()
    if PSEUDO_PROTOCOL in type:
        payloads += gen_pseudo_protocol(position)
    return payloads


def gen_function(position):
    tag = position.tag
    payloads = []
    if 'id' in tag.attrs:
        payload_obj = Payload()
        payload_obj.trigger = '#' + tag.attrs['id']
        for function in conf.functions:
            payload_obj.value = function.name
            payloads.append(payload_obj)
    return payloads


def gen_code():
    payloads = []
    for function in conf.functions:
        payload_obj = Payload()
        payload_obj.value = function.name
        payloads.append(payload_obj)
    return payloads


def gen_pseudo_protocol(position):
    '''
    :param suffix: 前缀
    :param prefix: 后缀
    :param position:位置信息
    :return: 生成伪协议的payload
    '''
    if isinstance(position, Position):
        payloads = []
        for function in conf.functions:
            payload_obj = Payload()
            original_payload = PSEUDO_PROTOCOL_NAME + ':' + function.name
            payload_obj.value = Agent.payload(
                pseudo_protocol_handler(PSEUDO_PROTOCOL_NAME) + ':' + function.name)
            payload_obj.trigger = '%s[%s=\'%s\']' % (position.tag.name, position.attr, original_payload)
            payloads.append(payload_obj)
        return payloads


def gen_inline(position):
    payloads = []
    # 当前漏洞所在标签的名字
    tag = position.tag
    name = tag.name
    for function in conf.functions:
        for action in conf.actions:
            payload_obj = Payload()
            if 'supported' in action:
                if name in action.supported:
                    value = action.name
                else:
                    continue
            else:
                if name not in action.unsupported:
                    value = action.name
                else:
                    continue

            value += '=%s' % function.name

            if action.trigger == '1':
                # 如果标签本身存在id，使用标签id
                if 'id' in tag.attrs:
                    id = tag.attrs['id']
                else:
                    id = randomStr(3)
                value += ' id=\'%s\'' % id
                payload_obj.trigger = '#' + id
            elif action.trigger == '3':
                value += ' ' + action.extra
            payload_obj.value = value
            payloads.append(payload_obj)
    return payloads


def gen_block():
    payloads = []
    for function in conf.functions:
        for action in conf.actions:
            name = action.name
            tags = []
            if 'supported' in action:
                tags = action.supported
            elif 'unsupported' in action:
                for _ in TAG:
                    if _ not in action.unsupported:
                        tags.append(_)
            for tag in tags:
                payload_obj = Payload()
                value = '<' + tag
                if action.trigger == '1':
                    id = randomStr(3)
                    value = value + ' id=\'%s\'' % id
                    payload_obj.trigger = '#' + id
                elif action.trigger == '3':
                    value = value + ' ' + action.extra
                payload_obj.value = value + ' ' + name + '=' + function.name + ' />'
                payloads.append(payload_obj)
    return payloads


def pseudo_protocol_handler(protocol_name):
    # 若检测等级大于1，对伪协议进行随机的html编码
    if conf.level > 1:
        from lib.core.common import random_escape
        return urllib.parse.quote(random_escape(protocol_name))
    else:
        return protocol_name


def genFullyTag():
    '''
    :param prefix: 前缀
    :param suffix: 后缀
    :return: fully.xml完整的payload
    '''
    payloads = []
    for tag in conf.fully:
        payload_obj = Payload()
        payload_obj.value = tag.payload
        if 'decode' in tag and tag.decode == 'url':
            payload_obj.encode = ENCODE_URL
        if 'trigger' in tag:
            payload_obj.trigger = tag.trigger
        payloads.append(payload_obj)
    return payloads


def loadPayloads():
    for payloadFile in PAYLOAD_XML_FILES:
        payloadFilePath = os.path.join(paths.XSSING_PAYLOADS_PATH, payloadFile)
        try:
            doc = et.parse(payloadFilePath)
        except Exception as ex:
            errMsg = "something appears to be wrong with "
            errMsg += "sure that you haven't made any changes to it"
            raise XssingInstallationException(errMsg)
        root = doc.getroot()
        parseXmlNode(root)


def loadBoundaries():
    try:
        doc = et.parse(paths.BOUNDARIES_XML)
    except Exception as ex:
        errMsg = "something appears to be wrong with "
        errMsg += "sure that you haven't made any changes to it"
        raise XssingInstallationException(errMsg)

    root = doc.getroot()
    parseXmlNode(root)


def parseXmlNode(node):
    for element in node.getiterator("boundary"):
        boundary = AttribDict()

        for child in element.getchildren():
            if child.text:
                boundary[child.tag] = child.text
            else:
                boundary[child.tag] = None

        conf.boundaries.append(boundary)

    for element in node.getiterator("function"):
        functions = AttribDict()

        for child in element.getchildren():
            if child.text:
                functions[child.tag] = child.text
            else:
                functions[child.tag] = None

        conf.functions.append(functions)

    for element in node.getiterator("fully"):
        fully = AttribDict()

        for child in element.getchildren():
            if child.text:
                fully[child.tag] = child.text
            else:
                fully[child.tag] = None

        conf.fully.append(fully)

    for element in node.getiterator("action"):
        actions = AttribDict()

        for child in element.getchildren():
            if child.text and child.text.strip():
                text = child.text
                if child.tag in ('supported', 'unsupported'):
                    text = str(text).split('|')
                actions[child.tag] = text
            else:
                actions[child.tag] = None
        conf.actions.append(actions) if len(actions) > 0 else None
