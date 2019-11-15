#
import os
from lib.core.data import kb, conf
from lib.core.settings import PAYLOAD_XML_FILES, INLINE, CODE, BLOCK, TAG, XSS_MESSAGE, PSEUDO_PROTOCOL, \
    PSEUDO_PROTOCOL_NAME, BLOCK_BOUNDARY, INLINE_BOUNDARY, INLINE_PSEUDO_PROTOCOL_BOUNDARY
from lib.core.data import paths
from lib.core.exceptions import XssingInstallationException
from lib.core.common import randomStr, absoluteUrlEncode
from xml.etree import ElementTree as et
from lib.core.datatype import AttribDict
from lib.core.datatype import Position
import urllib.parse


class Agent(object):
    @staticmethod
    def payload(payload):
        payload = conf.prefix + payload + conf.suffix
        return payload


def getPayload(position):
    payloads = []
    if len(kb.boundaries) == 0:
        return None
    for boundary in kb.boundaries:
        if isinstance(boundary, str):
            payloads += genPayload(type=BLOCK) if boundary == BLOCK_BOUNDARY else []
            payloads += genPayload(type=PSEUDO_PROTOCOL,
                                   position=position) if boundary == INLINE_PSEUDO_PROTOCOL_BOUNDARY else []
            payloads += gen_function(position) if boundary == INLINE_BOUNDARY else []
        else:
            suffix = boundary.suffix if 'suffix' in boundary else ''
            prefix = boundary.prefix
            payloads += genPayload(boundary.type, position, prefix=prefix, suffix=suffix)
    return payloads


def genPayload(type, position=None, prefix='', suffix=''):
    payloads = []
    if BLOCK in type:
        # 获取完整html tag，添加到payload中
        payloads = payloads + genFullyTag(prefix, suffix)
        payloads = payloads + gen_block(prefix, suffix)
    if INLINE in type:
        payloads += gen_inline(position, prefix, suffix)
    if CODE in type:
        payloads += gen_code()
    if PSEUDO_PROTOCOL in type:
        payloads += gen_pseudo_protocol(position, prefix, suffix)
    return payloads


def gen_function(position):
    tag = position.tag
    payloads = []
    if 'id' in tag.attrs:
        payload_dict = AttribDict()
        payload_dict.trigger = '#' + tag.attrs['id']
        for function in conf.functions:
            func = randomStr(2)
            function = function_handler(function, func)
            payload_dict.payload = function
            payload_dict.func = func
            payloads.append(payload_dict)
    return payloads


def gen_code():
    payloads = []
    for function in conf.functions:
        func = randomStr(2)
        payload_dict = AttribDict()
        function = function_handler(function, func)
        payload = Agent.payload(function)
        payload_dict.payload = payload
        payload_dict.func = func
        payloads.append(payload_dict)
    return payloads


def gen_pseudo_protocol(position, prefix='', suffix=''):
    '''
    :param suffix: 前缀
    :param prefix: 后缀
    :param position:位置信息
    :return: 生成伪协议的payload
    '''
    if isinstance(position, Position):
        payloads = []
        for function in conf.functions:
            func = randomStr(2)
            payload_dict = AttribDict()
            function = function_handler(function, func)
            original_payload = Agent.payload(prefix + PSEUDO_PROTOCOL_NAME + ':' + function + suffix)
            payload_dict.payload = Agent.payload(
                prefix + pseudo_protocol_handler(PSEUDO_PROTOCOL_NAME) + ':' + function + suffix)
            payload_dict.func = func
            payload_dict.trigger = '%s[%s=\'%s\']' % (position.tag.name, position.attr, original_payload)
            payloads.append(payload_dict)
        return payloads


def gen_inline(position, prefix, suffix):
    payloads = []
    # 当前漏洞所在标签的名字
    tag = position.tag
    name = tag.name
    for function in conf.functions:
        func = randomStr(1)
        content = randomStr(2)
        function = function_handler(function, func)
        for action in conf.actions:
            payload_dict = AttribDict()
            payload = content + prefix + ' '
            if 'supported' in action:
                if name in action.supported:
                    payload += action.name
                else:
                    continue
            elif 'unsupported' in action:
                if name not in action.unsupported:
                    payload += action.name
                else:
                    continue

            payload += '=%s' % function

            if action.trigger == '1':
                # 如果标签本身存在id，使用标签id
                if 'id' in tag.attrs:
                    id = tag.attrs['id']
                else:
                    id = randomStr(3)
                payload += ' id=\'%s\'' % (id)
                payload_dict.trigger = '#' + id
            elif action.trigger == '3':
                payload += ' ' + action.extra
            payload_dict.payload = Agent.payload(payload) + suffix
            payload_dict.func = func
            payloads.append(payload_dict)
    return payloads


def gen_block(prefix, suffix):
    payloads = []
    for function in conf.functions:
        func = randomStr(1)
        function = function_handler(function, func)
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
                payload_dict = AttribDict()
                payload = prefix + '<' + tag
                if action.trigger == '1':
                    id = randomStr(3)
                    payload = payload + ' id=\'%s\'' % (id)
                    payload_dict.trigger = '#' + id
                elif action.trigger == '3':
                    payload = payload + ' ' + action.extra
                payload_dict.payload = payload + ' ' + name + '=' + function + ' />' + suffix
                payload_dict.func = func
                payloads.append(payload_dict)
    return payloads


def function_handler(function, func_name):
    function = function.name.replace('?', func_name).replace('$', XSS_MESSAGE)
    return function


def pseudo_protocol_handler(protocol_name):
    # 若检测等级大于1，对伪协议进行随机的html编码
    if conf.level > 1:
        from lib.core.common import random_escape
        return urllib.parse.quote(random_escape(protocol_name))
    else:
        return protocol_name


def genFullyTag(prefix, suffix):
    '''
    :param prefix: 前缀
    :param suffix: 后缀
    :return: fully.xml完整的payload
    '''
    payloads = []
    for tag in conf.fully:
        func = randomStr(1)
        payload_dict = AttribDict()
        payload = tag.payload
        payload_dict.func = func
        msg = XSS_MESSAGE
        if 'decode' in tag and tag.decode == 'url':
            func = absoluteUrlEncode(func)
            msg = absoluteUrlEncode(str(XSS_MESSAGE))
        else:
            func = urllib.parse.quote(func)
        payload = prefix + payload.replace('?', func).replace('$', msg) + suffix
        payload_dict.payload = payload
        payloads.append(payload_dict)
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
