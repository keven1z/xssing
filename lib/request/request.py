import copy
import warnings
import requests
from lib.core.data import logger
from lib.request.url import WrappedUrl
from lib.core.settings import TIMEOUT

warnings.filterwarnings('ignore')


def open(wrappedUrl, connection_timeout=None, timeout=None):
    assert isinstance(wrappedUrl, WrappedUrl)
    kwargs = dict(wrappedUrl.kwargs)

    if connection_timeout:
        kwargs['connection_timeout'] = connection_timeout
    kwargs['timeout'] = timeout if timeout is not None else TIMEOUT
    method = kwargs.pop('method')
    url = wrappedUrl.url
    resp = _request(method, url, **kwargs)
    return resp


def _request(method, url, **kwargs):
    requests_header = ["params", "data", "headers", "cookies", "files", "auth", "timeout", "allow_redirects",
                       "proxies", "stream", "verify", "cert", "json"]
    user_defined_args = dict(kwargs)
    upa = copy.deepcopy(user_defined_args)
    for key in upa.keys():
        if key not in requests_header:
            user_defined_args.pop(key)
    kwargs = user_defined_args
    if url.startswith('https:'):
        kwargs['verify'] = False
    if 'data' in kwargs:
        data = kwargs['data']
        data_dict = {}
        if isinstance(data, str):
            list = data.split('&')
            for l in list:
                e = l.split('=')
                data_dict[e[0]] = e[1]
            kwargs['data'] = data_dict

    resp = _do_request(method, url, **kwargs)
    return resp


def _do_request(method, url, **kwargs):
    resp = None
    try:
        resp = requests.request(method, url, **kwargs)
    except Exception as e:
        logger.warn(e)
    finally:
        if resp is not None:
            if resp.status_code != 200:
                logger.warn('%s(%s)' % (resp.reason, resp.status_code))
            return resp

