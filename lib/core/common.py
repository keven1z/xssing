from lib.core.settings import BANNER, DEFAULT_DELIMITER
from lib.core.data import conf
from lib.core.enums import PLACE, HTTP
from lib.request.url import WrappedUrl
from lib.core.data import kb, paths
import sys
import string
import random
import copy
import html
import os


def banner():
    """
    This function prints sqlmap banner with its version
    """

    if not any(_ in sys.argv for _ in ("--version", "--api")) and not conf.get("disableBanner"):
        _ = BANNER


def dataToStdout(data, type=0):
    """
    :param data:
    :param type: 1:info 2:warn 3:error
    :return:
    """
    try:
        if type == 1:
            data = '[i] %s\n' % data
        elif type == 2:
            data = '[!] %s\n' % data
        elif type == 3:
            data = '[-] %s\n' % data
        sys.stdout.write(data)
        sys.stdout.flush()
    except IOError:
        pass


def randomStr(length=4, lowercase=True):
    """
    Returns random string value with provided number of characters
    """
    choice = random.choice
    if lowercase:
        retVal = "".join(choice(string.ascii_lowercase) for _ in range(0, length))
    else:
        retVal = "".join(choice(string.ascii_letters) for _ in range(0, length))

    return retVal


def randomInt(length=4, seed=None):
    choice = random.choice
    return int("".join(choice(string.digits if _ != 0 else string.digits.replace('0', '')) for _ in range(0, length)))


def absoluteUrlEncode(string):
    if isinstance(string, str):
        output = ''
        for s in string:
            output = output + '%' + hex(ord(s)).replace('0x', '')
        return output
    else:
        raise TypeError


def payloadCombined(target, place, parameter, payload):
    assert isinstance(target, WrappedUrl)
    _ = copy.deepcopy(target)
    if place == PLACE.GET:
        query = target.query
        if query is None:
            raise ValueError
        query_update_list = []
        for part in query.split(DEFAULT_DELIMITER):
            if '=' in part:
                name, value = part.split('=', 1)
                name = name.strip()
                if name == parameter:
                    query_update_list.append(parameter + '=' + payload)
                else:
                    query_update_list.append(part)
        query = '&'.join(query_update_list)
        _.query = query
        return _

    elif place == PLACE.POST:
        data = target.post_data
        if data is None:
            raise ValueError
        query_update_list = []
        for part in data.split(DEFAULT_DELIMITER):
            if '=' in part:
                name, value = part.split('=', 1)
                name = name.strip()
                if name == parameter:
                    query_update_list.append(parameter + '=' + payload)
                else:
                    query_update_list.append(part)
        data = '&'.join(query_update_list)
        _.post_data = data
        return _


def findParameterName(target, parameter=None):
    assert isinstance(target, WrappedUrl)
    # 处理get参数
    if conf.method == HTTP.GET.value:
        if target.query is None:
            return
        kb.places.append(PLACE.GET)
        if parameter is not None:
            kb.parameters.append(parameter) if parameter in target.query else None
        else:
            for part in target.query.split(DEFAULT_DELIMITER):
                if '=' in part:
                    name, value = part.split('=', 1)
                    name = name.strip()
                    kb.parameters.append(name)
    # 处理post参数
    elif conf.method == HTTP.POST.value:
        if target.post_data is None:
            return
        kb.places.append(PLACE.POST)
        if parameter is not None:
            kb.parameters.append(parameter) if parameter in target.post_data else None
        else:
            for part in target.post_data.split(DEFAULT_DELIMITER):
                if '=' in part:
                    name, value = part.split('=', 1)
                    name = name.strip()
                    kb.parameters.append(name)


def setPaths(rootPath):
    paths.XSSING_DATA_PATH = os.path.join(rootPath, "data")
    paths.XSSING_XML_PATH = os.path.join(paths.XSSING_DATA_PATH, 'xml')
    paths.XSSING_PAYLOADS_PATH = os.path.join(paths.XSSING_XML_PATH, 'payloads')
    paths.BOUNDARIES_XML = os.path.join(paths.XSSING_XML_PATH, 'boundaries.xml')


def readInput(message, default=None, boolean=False):
    """
    Reads input from terminal
    """

    if "\n" in message:
        message += "%s> " % ("\n" if message.count("\n") > 1 else "")
    elif message[-1] == ']':
        message += " "

    retVal = input(message)
    if retVal and default and isinstance(default, str) and len(default) == 1:
        retVal = retVal.strip()

    if boolean:
        retVal = retVal.strip().upper() == 'Y'

    return retVal or ""


def random_escape(parameter):
    '''
    随机对一个字符进行转义
    :param parameter:
    :return:
    '''
    if isinstance(parameter, str):
        length = len(parameter)
        if length < 1:
            raise ValueError('parameter\'s length not eq 0')
        index = random.randint(0, length - 1)
        encode_element = '&#%s;' % str(ord(parameter[index]))
        return parameter[:index] + encode_element + parameter[index + 1:]
    else:
        raise TypeError('htmlencode must be str,not %s' % type(parameter))
