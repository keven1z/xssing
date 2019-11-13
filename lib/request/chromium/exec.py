class ChromiumRequestError(IOError):
    pass


class InvalidURL(ChromiumRequestError, ValueError):
    pass


class HTTPError(ChromiumRequestError):
    """An HTTP error occurred."""
    pass


class ConnectionError(ChromiumRequestError):
    pass
