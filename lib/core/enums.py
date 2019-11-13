from enum import Enum


class HTTP(Enum):
    GET = 'GET'
    POST = 'POST'


class PLACE(Enum):
    GET = 'GET'
    POST = 'POST'


class POSITION(Enum):
    LABEL_INSIDE = 'lable'
    NON_EVE_ATTR_INSIDE = 'non-event attributes'
    EVE_ATTR_INSIDE = 'event attributes'
    COMMENT = 'comment'
    JS_COMMENT = 'javascript comment'
    JS_VALUE = 'javascript variable'
    SPECIAL_ATTR = 'special attribute'

