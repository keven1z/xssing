from lib.request.chromium.drive import HeadlessRequest
from lib.request.url import WrappedUrl
from lib.core.settings import XSS_MESSAGE


class XSSCheckRequest(HeadlessRequest):
    def __init__(self, browser):
        super().__init__(browser)
        self.func = None
        self.msg = None
        self.trigger = None
        self.found_xss = False
        self.payload = ''
        self.dialogExits = False

    def _xss_auditor(self, message):
        message = str(message)
        if message in [str(XSS_MESSAGE), '[\'' + str(XSS_MESSAGE) + '\']']:
            self.found_xss = True

    async def before_request(self, page):
        # 禁止弹出框
        if self.func:
            await page.exposeFunction(
                self.func, lambda message: self._xss_auditor(message)
            )

    async def after_request(self, page):
        if self.trigger is not None:
            element = await page.querySelector(self.trigger)
            if element is not None:
                await element.click()
                await page.waitForSelector(self.trigger)

    def is_exist_xss(self):
        return self.found_xss

    async def pre_request(self, url, method, **kwargs):
        self.func = kwargs['func'] if 'func' in kwargs else None
        self.trigger = kwargs['trigger'] if 'trigger' in kwargs else None
        return await super().pre_request(url, method, **kwargs)

    def clear(self):
        self.found_xss = False
