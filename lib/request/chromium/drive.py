from asyncio import CancelledError
import copy
from pyppeteer import launch
from lib.request.chromium.exec import InvalidURL, ConnectionError, ChromiumRequestError
from urllib.parse import urlparse, urlunparse
import asyncio
from lib.request.url import WrappedUrl
from asyncio import InvalidStateError,coroutine
POST = 'POST'
GET = 'GET'
TIMEOUT = 1000


async def run_browser():
    browser = await launch(headless=True, ignoreHTTPSErrors=True, autoClose=False,
                           args=['--disable-xss-auditor', '--no-sandbox'])
    return browser


class HeadlessRequest(object):

    def __init__(self):
        self.loop = asyncio.get_event_loop()

    def request(self, wrappedUrl):
        try:
            if isinstance(wrappedUrl, WrappedUrl):
                task = asyncio.wait_for(self.pre_request(wrappedUrl.url, **wrappedUrl.kwargs), 2000)
                return self.loop.run_until_complete(task)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except RuntimeError:
            pass
        except ChromiumRequestError as e:
            raise ChromiumRequestError(e)

    async def pre_request(self, url, method, **kwargs):
        """
            在发送request之前对值做校验
        """
        requests_param = ["headers", "cookies", "data", "json"]
        user_defined_args = dict(kwargs)
        upa = copy.deepcopy(user_defined_args)
        for key in upa.keys():
            if key not in requests_param:
                user_defined_args.pop(key)
        kwargs = user_defined_args
        try:
            return await self._request(url, method, **kwargs)
        except ChromiumRequestError as e:
            raise ChromiumRequestError(e)

    async def _request(self, url, method, headers=None, cookies=None, data=None, json=None):
        p = self.prepare_request(url, method, headers=headers, cookies=cookies, data=data, json=json)
        method = p.method
        headers = p.headers
        cookies = p.cookies
        body = p.body

        try:
            return await self.fetch(url, method, cookies=cookies, body=body, headers=headers)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as e:
            raise ChromiumRequestError(e)

    def prepare_request(self, url, method, headers=None, cookies=None, data=None, json=None):
        '''
        为请求做准备
        :param url: url
        :param method: 请求方法
        :param headers: 请求header
        :param cookies: cookies
        :param data: 请求数据
        :param json: 请求的json数据
        :return: @PrepareRequest对象
        '''
        p = PrepareRequest()
        p.prepare(url, method, headers, cookies, data, json=json)
        return p

    async def request_check(self, req, headers, body=None, method=GET):
        if POST == method.upper():
            overrides = {
                'method': method,
                'postData': body,
                'headers': headers
            }
        else:
            overrides = {
                'headers': headers
            }
        if req.resourceType in ['image', 'media', 'websocket']:
            await req.abort()
        else:
            await req.continue_(overrides=overrides)

    async def fetch(self, url, method, cookies=None, body=None, headers=None):
        if headers is None:
            headers = {}
        browser = await run_browser()
        page = await browser.newPage()
        await page.setRequestInterception(True)
        await self.before_request(page)
        # 禁止弹出框
        page.on('dialog', lambda dialog: dialog.dismiss())
        page.on('request',
                lambda req: asyncio.ensure_future(self.request_check(req, headers, body=body, method=method)))
        await page.setCookie(*cookies) if cookies is not None else None
        try:
            response = await page.goto(url)
            await self.after_request(page)
            await page.waitFor(100)
            return response
        except CancelledError as e:
            raise ChromiumRequestError(e)
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except InvalidStateError:
            raise ConnectionError('The URL(%s) connect error' % url)
        finally:
            await browser.close()

    async def before_request(self, page):
        pass

    async def after_request(self, page):
        pass


class PrepareRequest(object):
    def __init__(self):
        #: HTTP verb to send to the server.
        self.method = None
        #: HTTP URL to send the request to.
        self.url = None
        #: dictionary of HTTP headers.
        self.headers = dict()
        # after prepare_cookies is called
        self.cookies = list()
        #: request body to send to the server.
        self.body = None

        self.host = None

    def prepare(self, url, method, headers=None, cookies=None, data=None, json=None):
        self.prepare_url(url)
        self.prepare_method(method)
        self.prepare_headers(headers)
        self.prepare_cookies(cookies)
        self.prepare_body(data, json=json)

    def prepare_url(self, url):
        if isinstance(url, list):
            self.url = url
            return
        if isinstance(url, bytes):
            url = url.decode('utf8')
            # Remove leading whitespaces from url
        url = url.lstrip()

        try:
            parseResult = urlparse(url=url)
        except Exception as e:
            raise InvalidURL(*e.args)
        if not parseResult.scheme or parseResult.scheme == '':
            error = "Invalid URL {0!r}: No schema supplied. Perhaps you meant http://{0}?"
            raise InvalidURL(error.format(url))
        if not parseResult.netloc or parseResult.netloc == '':
            raise InvalidURL("Invalid URL %r: No host supplied" % url)
        self.host = parseResult.netloc
        self.url = urlunparse((parseResult.scheme, parseResult.netloc, parseResult.path, parseResult.params,
                               parseResult.query, parseResult.fragment))

    def prepare_method(self, method):
        self.method = method
        if self.method is not None:
            self.method = self.method.upper()

    def prepare_cookies(self, cookies):
        if isinstance(cookies, dict):
            if isinstance(cookies, dict):
                for key, value in cookies.items():
                    self.cookies.append({'name': key, 'value': value, 'domain': self.host})
        elif isinstance(cookies, str):
            cs = cookies.split(';')
            for _ in cs:
                e = _.split('=')
                if e[0] and e[1]:
                    self.cookies.append({'name': e[0].lstrip(), 'value': e[1].lstrip(), 'domain': self.host})

    def prepare_body(self, data, json):
        content_type = None
        body = None
        if not data and json is not None:
            content_type = 'application/json'
            body = json
        if data:
            body = data
            if hasattr(data, 'read'):
                content_type = None
            else:
                content_type = 'application/x-www-form-urlencoded'
        if content_type and ('content-type' not in self.headers):
            self.headers['Content-Type'] = content_type

        self.body = body

    def prepare_headers(self, headers):
        if headers:
            for header in headers.items():
                name, value = header
                self.headers[name] = value

