import requests


class RequestEngine:
    def __init__(self, base_headers=None, timeout=10):
        self.base_headers = base_headers or {}
        self.timeout = timeout

    def send(self, method, url, headers=None, params=None, data=None):
        final_headers = self.base_headers.copy()
        if headers:
            final_headers.update(headers)

        return requests.request(
            method=method,
            url=url,
            headers=final_headers,
            params=params,
            json=data,
            timeout=self.timeout
        )
