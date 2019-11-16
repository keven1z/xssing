# coding=utf-8
from typing import Tuple

VERSION = "2.1.2"
AUTHOR = "x1001"
BANNER = '''                 _             
                (_)            
 _   _  ___  ___ _ ____   ____ 
( \ / )/___)/___| |  _ \ / _  |  
 ) X (|___ |___ | | | | ( ( | |
(_/ \_(___/(___/|_|_| |_|\_|| |
                        (_____|
''' + "\t\t\tby " + AUTHOR + " {version:" + VERSION + "}\n"

TIMEOUT = 10
DEFAULT_DELIMITER = '&'

# xss vuln postion
POS_LABEL_INSIDE = 1  # 普通标签内
POS_NON_EVE_ATTR_INSIDE = 2  # 非事件属性
POS_EVE_ATTR_INSIDE = 3  # 事件属性
POS_COMMENT = 4  # 注释中
POS_JS_COMMENT = 5  # JS的注释中
POS_JS_VALUE = 6  # JS的值中
POS_SPECIAL_ATTR = 7  # 特殊的属性内
POS = {'LABEL_INSIDE': 1, 'NON_EVE_ATTR_INSIDE': 2, 'EVE_ATTR_INSIDE': 3, 'COMMENT': 4, 'JS_COMMENT': 5, 'JS_VALUE': 6,
       'SPECIAL_ATTR': 7}
functions = (  # JavaScript functions to get a popup
    '(?)($)',
    '(?)`$`', 'a=?,a($)')
JS_SUFFIX = [';//']

REPLACE_TAG = '[TAG]'
PAYLOAD_XML_FILES = ["actions.xml", "fully.xml", "functions.xml"]
CLOSED_LABEL = ['title', 'style', 'script', 'textarea', 'noscript', 'pre', 'xmp', 'iframe']
# 注入的类型
INLINE = '1'  # 内联注入
BLOCK = '2'  # 块注入
CODE = '3'  # 代码注入
PSEUDO_PROTOCOL = '4'  # 伪协议注入
# 特殊边界
BLOCK_BOUNDARY = '1'
INLINE_PSEUDO_PROTOCOL_BOUNDARY = '2'
INLINE_BOUNDARY = '3'
SPECIAL_ATTR = {
    'href',
    'action',
    'formaction'
}
NON_EVENT_ATTRIBUTE = (
    'accesskey',
    'class',
    'children',
    'contenteditable',
    'dir',
    'draggable',
    'dropzone',
    'hidden',
    'id',
    'value',
    'lang',
    'spellcheck',
    'style',
    'tabindex',
    'title',
    'src',
    'translate')

EVENT_ATTRIBUTE = (
    'onload',
    'onunload',
    'onblur',
    'onchange',
    'oncontextmenu',
    'onfocus',
    'onforminput',
    'oninput',
    'oninvalid',
    'onreset',
    'onselect',
    'onsubmit',
    'onkeydown',
    'onkeypress',
    'onkeyup',
    'onclick',
    'ondblclick',
    'ondrag',
    'onmousedown',
    'onmousemove',
    'onmouseout',
    'onmouseover',
    'onmouseup',
    'onmousewheel',
    'onscroll',
    'onerror',
    'oncanplay',
    'oncanplaythrough',
    'ondurationchangeNew',
    'onemptiedNew',
    'onendedNew',
    'onplayNew',
    'onseeked',
    'onseeking'
)
TAG: Tuple[str, str, str, str, str] = (
    'svg',
    'button',
    'details',
    'input',
    'object'
)

# 伪协议
PSEUDO_PROTOCOL_NAME = 'javascript'
# 日志等级
LEVEL_PAYLOAD = 9

XSS_MESSAGE = '9'
XSS_USERAGENT = {'User-Agent': 'xssing(%s)_for_test' % VERSION}
# 探测位置字符串
DETECTOR = '$parameter$'

# payload编码
ENCODE_NONE = None
ENCODE_URL = 'url'
