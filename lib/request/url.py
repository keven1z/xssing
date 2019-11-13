from urllib.parse import urlparse, urlunparse
from lib.core.enums import HTTP


class WrappedUrl(object):
    """docstring for WrappedUrl"""

    def __init__(self, url, **kwargs):
        self._request = WrappedRequest(**kwargs)
        self._url = url

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, url):
        self._url = url

    @property
    def port(self):
        components = urlparse(self._url)
        port = components.port
        if port is None:
            if components.scheme == 'http':
                port = 80
            elif components.scheme == 'https':
                port = 443
        return port

    @property
    def query(self):
        components = urlparse(self._url)
        return components.query

    @query.setter
    def query(self, query):
        components = urlparse(self._url)
        url = urlunparse(
            (components.scheme, components.netloc, components.path, components.params, query, None))
        self._url = url

    @property
    def hostname(self):
        components = urlparse(self._url)
        hostname = components.hostname
        return hostname

    @property
    def json(self):
        return self._request.json

    @property
    def scheme(self):
        components = urlparse(self._url)
        scheme = components.scheme
        return scheme

    @property
    def method(self):
        return self._request.method

    @method.setter
    def method(self, method):
        self._request.method = method

    @property
    def req_headers(self):
        return self._request.headers

    @req_headers.setter
    def req_headers(self, headers):
        self._request.headers = headers

    @property
    def post_data(self):
        return self._request.post_data

    @post_data.setter
    def post_data(self, data):
        self._request.post_data = data

    @property
    def cookies(self):
        return self._request.cookies

    @property
    def kwargs(self):
        return self._request.kwargs

    @kwargs.setter
    def kwargs(self, kwargs):
        self._request.kwargs = kwargs

    def __str__(self):
        return '(%s %s)' % (self.__class__, self.url)


class WrappedRequest(object):
    def __init__(self, method=HTTP.GET.value, headers={}, proxy=None, auth=None, cookies=None, \
                 data='', timeout=None, allow_redirects=False, json=None, **kwargs):
        kwargs = dict(kwargs)
        kwargs['method'] = method.upper()
        kwargs['allow_redirects'] = allow_redirects
        kwargs['headers'] = dict(headers)
        if proxy:
            kwargs['proxy'] = proxy
        if auth:
            kwargs['auth'] = auth
        if data:
            kwargs['data'] = data
        if timeout:
            kwargs['timeout'] = timeout
        if json:
            kwargs['json'] = json
        if cookies:
            cookie_dict = {}
            if isinstance(cookies, str):
                cookie_list = cookies.split(';')
                for element in cookie_list:
                    e = element.split('=')
                    if e[0] and e[1]:
                        e[0] = e[0].replace(' ', '')  # delete space
                        e[1] = e[1].replace(' ', '')  # delete space
                    cookie_dict[e[0]] = e[1]
                kwargs['cookies'] = cookie_dict

        self._kwargs = kwargs

    @property
    def method(self):
        return self._kwargs.get('method')

    @method.setter
    def method(self, method):
        self._kwargs['method'] = method

    @property
    def allow_cache(self):
        return self._kwargs.get('allow_cache')

    @allow_cache.setter
    def allow_cache(self, allow_cache):
        self._kwargs['allow_cache'] = allow_cache

    @property
    def headers(self):
        return self._kwargs.get('headers')

    @headers.setter
    def headers(self, headers):
        self._kwargs['headers'] = headers

    @property
    def json(self):
        return self._kwargs.get('json')

    @json.setter
    def json(self, json):
        self._kwargs['json'] = json

    @property
    def cookies(self):
        return self._kwargs.get('cookies')

    @cookies.setter
    def cookies(self, cookies):
        self._kwargs['cookies'] = cookies

    @property
    def post_data(self):
        return self._kwargs.get('data')

    @post_data.setter
    def post_data(self, data):
        self._kwargs['data'] = data

    @property
    def kwargs(self):
        return self._kwargs

    @kwargs.setter
    def kwargs(self, kwargs):
        self._kwargs = kwargs

    def __str__(self):
        return '<%s %s>' % (self.__class__, self.method)


