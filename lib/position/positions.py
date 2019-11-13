# _*_coding=utf-8_*_
from abc import abstractmethod, ABC, ABCMeta

from bs4 import BeautifulSoup
from lib.core.datatype import Position
from lib.core.settings import NON_EVENT_ATTRIBUTE, EVENT_ATTRIBUTE, SPECIAL_ATTR
from lib.core.enums import POSITION
from bs4.element import NavigableString, Comment, Tag


class PositionChecker(metaclass=ABCMeta):
    def __init__(self, page, payload):
        self.bs4 = BeautifulSoup(page, 'html.parser')
        self.payload = payload

    def check(self):
        return self._check()

    @abstractmethod
    def _check(self):
        pass


class AttributeChecker(PositionChecker):

    def _check(self):
        bs4 = self.bs4
        payload = self.payload
        positions = []
        # 判断非事件属性
        for non_eve_attr in NON_EVENT_ATTRIBUTE:
            tag = bs4.find(attrs={non_eve_attr: payload})
            if isinstance(tag, Tag):
                position = Position()
                position.line = str(tag)
                position.tag = tag
                position.pos = POSITION.NON_EVE_ATTR_INSIDE
                positions.append(position)
        # 判断事件型属性
        for eve_attr in EVENT_ATTRIBUTE:
            tag = bs4.find(attrs={eve_attr: payload})
            if isinstance(tag, Tag):
                position = Position()
                position.line = str(tag)
                position.tag = tag
                position.pos = POSITION.EVE_ATTR_INSIDE
                positions.append(position)

        for eve_attr in SPECIAL_ATTR:
            tag = bs4.find(attrs={eve_attr: payload})
            if isinstance(tag, Tag):
                position = Position()
                position.line = str(tag)
                position.tag = tag
                position.pos = POSITION.SPECIAL_ATTR
                position.attr = eve_attr
                positions.append(position)
        return positions


class BlockChecker(PositionChecker):
    def _check(self):
        bs4 = self.bs4
        payload = self.payload
        positions = []
        comments = bs4.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            if payload in str(comment):
                position = Position()
                position.pos = POSITION.COMMENT
                position.line = '<!--... %s ...-->' % str(comment)
                position.tag = comment  # TODO test
                positions.append(position)
                return positions
        inBody = bs4.find(text=payload)
        bs4.find()
        if inBody is None:  # 检测是否在body标签内
            body = bs4.body
            if body is not None:
                text = body.text
                line = '<body>...[PARAMETER]...</body>'
                if text.find(payload) != -1:
                    position = Position()
                    position.pos = POSITION.LABEL_INSIDE
                    position.line = line
                    position.tag = body
                    positions.append(position)
                    return positions
                contents = body.contents
                for content in contents:  # first method
                    if isinstance(content, NavigableString) and content.find(payload) != -1:
                        position = Position()
                        position.pos = POSITION.LABEL_INSIDE
                        position.line = line
                        position.tag = body
                        positions.append(position)
                        return positions

        elif isinstance(inBody, NavigableString):
            parent_tag = inBody.parent
            if isinstance(parent_tag, Tag):  # TODO test
                position = Position()
                position.line = str(parent_tag)
                position.tag = parent_tag
                position.pos = POSITION.LABEL_INSIDE
                positions.append(position)
        return positions


class JsScriptChecker(PositionChecker):
    def _check(self):
        bs4 = self.bs4
        payload = self.payload
        positions = []
        scripts = bs4.find_all('script')
        for script in scripts:
            key_str = script.text
            if not isinstance(key_str, str) and key_str.find(payload) != -1:
                continue
            line_list = key_str.split('\r\n') if '\r\n' in key_str else key_str.split('\n')
            for line in line_list:
                pos = line.find(payload)
                if pos != -1:
                    position = Position()
                    position.tag = script
                    position.line = line.strip()

                    is_comment = line.find('//', 0,
                                           pos - 1)  # 判断XSS_VERIFICATION之前是否有//，若存在，则判定为在js注释内，反之在值内
                    if is_comment != -1:
                        position.pos = POSITION.JS_COMMENT

                    else:
                        position.pos = POSITION.JS_VALUE
                    positions.append(position)
        return positions
